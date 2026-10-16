"""Ordinary-user composition for two fixed test-artifact installation groups.

The root command receives the complete hashed literal, never this source path.
These unsigned test artifacts do not qualify a signed production release.
"""
import hashlib
import os
import sys

BASE_SHA256 = "0d74190d6be9f1eb65b54ba49b87a547641b11fdd8f95073489f31874959708f"
TRAILER = b'\n\nif __name__ == "__main__":\n    sys.exit(main())\n'


def compose(base_bytes):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("composition_must_be_unprivileged")
    if (type(base_bytes) is not bytes or hashlib.sha256(base_bytes).hexdigest() != BASE_SHA256
            or not base_bytes.endswith(TRAILER)):
        raise ValueError("audited_base_mismatch")
    return base_bytes[:-len(TRAILER)] + EXTENSION.encode()


EXTENSION = r'''

# Closed test-only groups. No arbitrary destination, executable, or roster input.
TEST_GROUPS = {
    "runtime-fixture": {
        "purpose": "native_runtime_five_member_test_artifact_only",
        "releaseDirectory": BASE + "/c6831958218ddcc5b69c9753c4180272611faccc65da201a8298ba9e81bbce2e",
        "digest": "sha256:9aa53d406a0b84732fb9495da4b47063c90ced4d153c03065dd7c4f43dd72476",
        "bytes": 7355714,
        "names": ["runtime-fixture", "bin/boot", "bin/kernel-lifecycle", "bin/internal-communication", "bin/exported-status"]},
    "frontend-receipt": {
        "purpose": "native_frontend_receipt_one_member_test_artifact_only",
        "releaseDirectory": BASE + "/e3e04d6f8e9a0cdea412928ebef4d0b28f614c6fb7ac9df471fa6ed372d1145d",
        "digest": "sha256:57134e0d827c5467cddb85c279a38fdcb102ec913950a0a17c6843fc7eec6416",
        "bytes": 7509794,
        "names": ["agentmux-frontend-receipt-fixture"]}}
TEST_INPUT_CAP = 11 * 1024 * 1024


def test_plan(group):
    require(type(group) is str and group in TEST_GROUPS, "unknown_test_artifact_group")
    spec = TEST_GROUPS[group]
    root = spec["releaseDirectory"]
    return dict(schemaVersion="1.0.0", purpose=spec["purpose"], group=group,
                releaseDirectory=root, ancestors=ROOTS + [root] + ([root + "/bin"] if group == "runtime-fixture" else []),
                ownerUID=0, ownerGroup="wheel", directoryMode="0755", copyProtocol=PROTOCOL,
                readyForInstallation=True, members=[dict(relativePath=n, digest=spec["digest"],
                    bytes=spec["bytes"], mode="0555") for n in spec["names"]])


def validate_test_artifact(raw, group, expected_digest):
    expected = test_plan(group)
    require(type(raw) is bytes and len(raw) <= TEST_INPUT_CAP, "test_input_bounds")
    require(type(expected_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest), "test_plan_hash_shape")
    envelope = decode_json(raw)
    require(type(envelope) is dict and set(envelope) == {"installationPlanBase64", "payloadBase64"}, "test_envelope_fields")
    plan_raw = decode64(envelope["installationPlanBase64"], MAX_MANIFEST)
    require(sha(plan_raw) == expected_digest, "test_plan_hash_mismatch")
    plan = decode_json(plan_raw)
    require(type(plan) is dict and plan == expected and
            json.dumps(plan, sort_keys=True) == json.dumps(expected, sort_keys=True), "closed_test_plan_mismatch")
    spec = TEST_GROUPS[group]
    payload = decode64(envelope["payloadBase64"], spec["bytes"])
    require(len(payload) == spec["bytes"] and sha(payload) == spec["digest"], "test_payload_hash_mismatch")
    magic, cpu, _, kind = struct.unpack_from("<IIII", payload)
    require((magic, cpu, kind) == (0xFEEDFACF, 0x0100000C, 2), "test_native_arm64_required")
    return plan, payload


class TestArtifactInstaller(Installer):
    def install_group(self, plan, payload):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        parent = self.open_held("/", flags)
        self.admit(parent, True)
        self.chain.append(parent)
        for index, path in enumerate(ROOTS[1:], 1):
            parent = self.directory(parent, path.rsplit("/", 1)[1], path, create=index >= 3)
        root = plan["releaseDirectory"]
        release = self.directory(parent, root.rsplit("/", 1)[1], root, create=True, fresh=True)
        binaries = None
        if plan["group"] == "runtime-fixture":
            binaries = self.directory(release, "bin", root + "/bin", create=True, fresh=True)
        for member in plan["members"]:
            name = member["relativePath"]
            parent = binaries if name.startswith("bin/") else release
            self.file(parent, name.rsplit("/", 1)[-1], root + "/" + name, payload, member["digest"])
        self.fence()
        for handle in self.handles:
            if handle["created"] is not None:
                os.fsync(handle["fd"])


def test_artifact_main():
    ledger = dict(schemaVersion="1.0.0", purpose="fixed_native_test_artifact_setup_only", success=False,
                  mutationStarted=False, created=[], descriptors=[], nativeAllocations=[], causes=[],
                  cleanupFailed=False, retainedForReview=True, protectedLoaderQualified=False,
                  nativeProcessIdentityQualified=False, productionReleaseQualified=False)
    installer, result = None, 1
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1, "isolated_interpreter_required")
        for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, timeout)
        deadline = time.monotonic() + 120
        signal.alarm(120)
        if sys.argv[1:] == ["--fault-controls"]:
            require(os.getuid() != 0 and os.geteuid() != 0, "unprivileged_controls_required")
            ledger.update(closeout_fault_controls())
        else:
            require(len(sys.argv) == 4 and sys.argv[1] in ("--validate-only", "--install"), "test_artifact_arguments")
            plan, payload = validate_test_artifact(sys.stdin.buffer.read(TEST_INPUT_CAP+1), sys.argv[2], sys.argv[3])
            ledger.update(purpose=plan["purpose"], group=plan["group"], planDigest=sys.argv[3],
                          payloadDigest=sha(payload), payloadBytes=len(payload),
                          releaseDirectory=plan["releaseDirectory"], allInputVerified=True)
            if sys.argv[1] == "--install":
                require(os.getuid() == 0 and os.geteuid() == 0, "root_setup_required")
                installer = TestArtifactInstaller(NativePolicy(ledger, deadline), ledger, deadline)
                installer.admit_interpreter()
                os.umask(0o077)
                ledger["mutationStarted"] = True
                installer.install_group(plan, payload)
            else:
                require(os.getuid() != 0 and os.geteuid() != 0, "validation_must_be_unprivileged")
        ledger["success"], result = True, 0
    except Refused as error:
        ledger["errorCode"] = str(error)
        ledger["causes"].append(dict(stage="test_artifact_setup", code=str(error)))
    except Exception:
        ledger["errorCode"] = "test_artifact_operation_failed"
        ledger["causes"].append(dict(stage="test_artifact_setup", code="test_artifact_operation_failed"))
    finally:
        FinalizationSignals(ledger).install()
        if installer is not None:
            try:
                installer.close()
            except Exception:
                ledger["cleanupFailed"] = True
                ledger["causes"].append(dict(stage="test_artifact_closeout", code="test_artifact_closeout_interrupted"))
        signal.alarm(0)
        result = finish_ledger(ledger, result)
    return result


if __name__ == "__main__":
    sys.exit(test_artifact_main())
'''


if __name__ == "__main__":
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
