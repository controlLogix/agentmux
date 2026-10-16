"""Compose a fixed nine-member materializer as an ordinary user.

Use compose(base_bytes) before privilege elevation, hash the complete result,
and pass that literal result with -I -S -c. Never run this file as root.
The composed root program does not read or import checkout source files.
No installation or runtime qualification is authorized by composition.
"""
import hashlib
import os
import sys

BASE_SHA256 = "0d74190d6be9f1eb65b54ba49b87a547641b11fdd8f95073489f31874959708f"
TRAILER = b'\n\nif __name__ == "__main__":\n    sys.exit(main())\n'


def compose(base_bytes):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("composition_must_be_unprivileged")
    if (type(base_bytes) is not bytes
            or hashlib.sha256(base_bytes).hexdigest() != BASE_SHA256
            or not base_bytes.endswith(TRAILER)):
        raise ValueError("audited_base_mismatch")
    return base_bytes[:-len(TRAILER)] + EXTENSION.encode("utf-8")


EXTENSION = r'''

# Closed real-release extension. All functions above are the exact audited base.
PREPARED_DIGEST = "sha256:cca9d084cb8122b29582e5132d7e4a970f2078daa581d1355782ef882221af26"
RELEASE_DIRECTORY = BASE + "/050f4f5c4cf78920cc11be3d94f96a75008d19b21201f7663cd5100ed6ced96c"
KERNEL_DIGEST = "sha256:4b88f1e42b7978e9ce570a19f3b5b78ed1902740f4e6f4be1507e2ad6a20ef36"
RELEASE_MEMBERS = [
    ("release-manifest.json", "sha256:2bdacc2e7a732636f9ade3c13d4ddebeec9c5a954b22dec96626ced8291cb96b", 322, "0444"),
    ("protected-assembly.json", "sha256:44a812157366282c2df4097cff5a32a4c203295a72b45de19006060b524ae27d", 858, "0444"),
    ("release-authorization.json", "sha256:82f577275c7ad3c63d79509965b73ee112837fbe3cddf4ee8881c8c63aab837b", 347, "0444"),
    ("release-authorization.sig", "sha256:431b9dd46f06e322b6d0d89dee62267ca31f95a0926edb85e7b704158231c3aa", 64, "0444"),
    ("bin/boot", KERNEL_DIGEST, 6609922, "0555"),
    ("bin/kernel-lifecycle", KERNEL_DIGEST, 6609922, "0555"),
    ("bin/internal-communication", KERNEL_DIGEST, 6609922, "0555"),
    ("bin/exported-status", KERNEL_DIGEST, 6609922, "0555"),
    ("agentmux-runtime", "sha256:a4f038fbeab062503d7c3e30b65c5f8ab0ea4fe29a7f9658a5c647155f10522a", 13576450, "0555"),
]
RELEASE_PURPOSE = "reviewed_nine_member_native_darwin_arm64_materialization"
RELEASE_INPUT_CAP = 28 * 1024 * 1024


def release_members():
    return [dict(relativePath=n, digest=d, bytes=s, mode=m) for n, d, s, m in RELEASE_MEMBERS]


def validate_release(raw, expected_digest):
    require(type(raw) is bytes and len(raw) <= RELEASE_INPUT_CAP, "release_input_bounds")
    require(type(expected_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest), "release_plan_hash_shape")
    envelope = decode_json(raw)
    require(type(envelope) is dict and set(envelope) == {
        "preparedPlanBase64", "installationPlanBase64", "payloads"}, "release_envelope_fields")
    prepared_raw = decode64(envelope["preparedPlanBase64"], MAX_MANIFEST)
    require(sha(prepared_raw) == PREPARED_DIGEST, "prepared_plan_hash_mismatch")
    prepared = decode_json(prepared_raw)
    require(prepared["readyForInstallation"] is False and prepared["testOnlySigningKey"] is True,
            "prepared_authority_changed")
    require(prepared["releaseDirectory"] == RELEASE_DIRECTORY and
            [{k: member[k] for k in ("relativePath", "digest", "bytes", "mode")}
             for member in prepared["members"]] == release_members(), "prepared_members_changed")
    plan_raw = decode64(envelope["installationPlanBase64"], MAX_MANIFEST)
    require(sha(plan_raw) == expected_digest, "release_plan_hash_mismatch")
    plan = decode_json(plan_raw)
    expected = dict(schemaVersion="1.0.0", purpose=RELEASE_PURPOSE,
                    preparedPlanDigest=PREPARED_DIGEST, releaseDirectory=RELEASE_DIRECTORY,
                    ancestors=ROOTS + [RELEASE_DIRECTORY, RELEASE_DIRECTORY + "/bin"],
                    ownerUID=0, group="wheel", directoryMode="0755", members=release_members(),
                    copyProtocol=PROTOCOL, readyForInstallation=True)
    # Equality alone accepts bool as int in Python; compare canonical JSON too.
    require(type(plan) is dict and plan == expected and
            json.dumps(plan, sort_keys=True) == json.dumps(expected, sort_keys=True),
            "closed_installation_plan_mismatch")
    encoded = envelope["payloads"]
    sizes = {d: s for _, d, s, _ in RELEASE_MEMBERS}
    require(type(encoded) is dict and set(encoded) == set(sizes), "closed_payload_roster")
    payloads = {}
    for digest, size in sizes.items():
        content = decode64(encoded[digest], size)
        require(len(content) == size and sha(content) == digest, "release_payload_hash_mismatch")
        payloads[digest] = content
    for _, digest, _, mode in RELEASE_MEMBERS:
        if mode == "0555":
            magic, cpu, _, kind = struct.unpack_from("<IIII", payloads[digest])
            require((magic, cpu, kind) == (0xFEEDFACF, 0x0100000C, 2), "release_native_arm64_required")
    return plan, payloads


class ReleaseInstaller(Installer):
    def release_file(self, parent, member, payload):
        self.fence()
        name = member["relativePath"].rsplit("/", 1)[-1]
        path = RELEASE_DIRECTORY + "/" + member["relativePath"]
        mode = int(member["mode"], 8)
        created = self.creation_intent(path, "file")
        created.update(expectedDigest=member["digest"], expectedMode=member["mode"], creationAttempted=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        handle = self.open_held(path, flags, parent, name, created=created)
        self.admit(handle, False)
        os.fchown(handle["fd"], 0, 0)
        view = memoryview(payload)
        while view:
            count = os.write(handle["fd"], view[:65536])
            require(count > 0, "release_write_incomplete")
            view = view[count:]
        os.fsync(handle["fd"])
        self.hash_file(handle)
        require(created["actualDigest"] == member["digest"] and created["bytes"] == len(payload),
                "release_installed_hash_mismatch")
        os.fchmod(handle["fd"], mode)
        self.admit(handle, False)
        info = self.refresh(handle)
        require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1,
                "release_installed_metadata_mismatch")
        created["admitted"] = True

    def install_release(self, plan, payloads):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        parent = self.open_held("/", flags)
        self.admit(parent, True)
        self.chain.append(parent)
        for index, path in enumerate(ROOTS[1:], 1):
            parent = self.directory(parent, path.rsplit("/", 1)[1], path, create=index >= 3)
        release = self.directory(parent, RELEASE_DIRECTORY.rsplit("/", 1)[1], RELEASE_DIRECTORY,
                                 create=True, fresh=True)
        binaries = self.directory(release, "bin", RELEASE_DIRECTORY + "/bin", create=True, fresh=True)
        for member in plan["members"]:
            parent = binaries if member["relativePath"].startswith("bin/") else release
            self.release_file(parent, member, payloads[member["digest"]])
        self.fence()
        for handle in self.handles:
            if handle["created"] is not None:
                os.fsync(handle["fd"])


def release_schema_controls():
    # These rejection controls never allocate native policy or touch a destination.
    cases = [b'{}', b'{"payloads":{},"payloads":{}}', b'NaN', b'[]']
    for raw in cases:
        try:
            validate_release(raw, "sha256:" + "0" * 64)
        except (Refused, ValueError, TypeError, KeyError):
            continue
        raise Refused("release_schema_control_false_acceptance")
    for value in ("AB==", "YQ", "YQ==\n"):
        try:
            decode64(value, 1)
        except (Refused, ValueError):
            continue
        raise Refused("release_base64_control_false_acceptance")
    return {"releaseSchemaControlsPassed": 7}


def release_main():
    ledger = dict(schemaVersion="1.0.0", purpose=RELEASE_PURPOSE, success=False,
                  mutationStarted=False, created=[], descriptors=[], nativeAllocations=[],
                  causes=[], cleanupFailed=False, retainedForReview=True,
                  protectedLoaderQualified=False, nativeProcessIdentityQualified=False,
                  installedSignatureVerificationRequired=True)
    installer, result = None, 1
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1, "isolated_interpreter_required")
        for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, timeout)
        deadline = time.monotonic() + 120
        signal.alarm(120)
        if sys.argv[1:] in (["--self-test"], ["--fault-controls"]):
            require(os.getuid() != 0 and os.geteuid() != 0, "unprivileged_controls_required")
            ledger.update(release_schema_controls() if sys.argv[1] == "--self-test" else closeout_fault_controls())
        else:
            require(len(sys.argv) == 3 and sys.argv[1] in ("--validate-only", "--install"), "release_arguments")
            plan, payloads = validate_release(sys.stdin.buffer.read(RELEASE_INPUT_CAP + 1), sys.argv[2])
            ledger.update(planDigest=sys.argv[2], preparedPlanDigest=PREPARED_DIGEST,
                          releaseDirectory=RELEASE_DIRECTORY, allInputVerified=True,
                          members=release_members(), uniquePayloads=len(payloads))
            if sys.argv[1] == "--install":
                require(os.getuid() == 0 and os.geteuid() == 0, "root_setup_required")
                installer = ReleaseInstaller(NativePolicy(ledger, deadline), ledger, deadline)
                installer.admit_interpreter()
                os.umask(0o077)
                ledger["mutationStarted"] = True
                installer.install_release(plan, payloads)
            else:
                require(os.getuid() != 0 and os.geteuid() != 0, "validation_must_be_unprivileged")
        ledger["success"], result = True, 0
    except Refused as error:
        ledger["errorCode"] = str(error)
        ledger["causes"].append(dict(stage="release_setup", code=str(error)))
    except Exception:
        ledger["errorCode"] = "release_setup_operation_failed"
        ledger["causes"].append(dict(stage="release_setup", code="release_setup_operation_failed"))
    finally:
        FinalizationSignals(ledger).install()
        if installer is not None:
            try:
                installer.close()
            except Exception:
                ledger["cleanupFailed"] = True
                ledger["causes"].append(dict(stage="release_closeout", code="release_closeout_interrupted"))
        signal.alarm(0)
        result = finish_ledger(ledger, result)
    return result


if __name__ == "__main__":
    sys.exit(release_main())
'''


if __name__ == "__main__":
    # Composition reads only the fixed base as an ordinary user. The caller
    # owns private capture, full-source hashing, and review of the result.
    if sys.argv[1:] != ["--compose"] or os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("unprivileged_compose_only")
    path = "/Users/ryan/GitHub/agentmux/platform/launcher/testdata/darwin_protected_installer.py"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(262145)
    finally:
        os.close(fd)
    sys.stdout.buffer.write(compose(data))
