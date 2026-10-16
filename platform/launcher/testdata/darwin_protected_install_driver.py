"""Unprivileged, pinned installer driver. Execution needs separate human approval.

Default mode only records the exact proposed command. Never run this driver as
root. The root child receives reviewed code bytes, not a writable script path.
"""
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time

ROOT = "/Users/ryan/GitHub/agentmux"
CACHE = "/Users/ryan/.cache/agentmux-governance"
INPUT = CACHE + "/darwin-installer-envelope.HvmoIx/evidence"
SOURCE = ROOT + "/platform/launcher/testdata/darwin_protected_installer.py"
SOURCE_SHA = "0d74190d6be9f1eb65b54ba49b87a547641b11fdd8f95073489f31874959708f"
MANIFEST_SHA = "50fa419183c3e5e343996188d2ae45ed5c53e4aad5c0ef0156e4aa3397033d26"
ENVELOPE_SHA = "e58bbe4ab60d8c6fcacae8956e48571c0f92348272956c8cc78147f0fb23d64f"
PAYLOAD_SHA = "ab3e8296d4fe5235e5a1c3fbe2abb6727145290641bf0797a159921fde5ac955"
RELEASE = "/Library/Application Support/Agentmux/Protected/releases/63985d14edaa6bcc3c6f7103ce49ecb7f4b2deec213a4c261ca7ec73a48c0f9f"
PATHS = [RELEASE + "/" + p for p in (
    "fixture", "bin/boot", "bin/kernel-lifecycle",
    "bin/internal-communication", "bin/exported-status")]
PYTHON = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_closed(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("input_shape_refused")
        chunks = []
        count = 0
        while True:
            part = os.read(fd, min(65536, limit + 1 - count))
            if not part:
                break
            chunks.append(part)
            count += len(part)
            if count > limit:
                raise ValueError("input_bound_refused")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("input_changed")
        data = b"".join(chunks)
    finally:
        os.close(fd)  # A failed close prevents the caller from receiving bytes.
    return data


def record(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())


def main():
    if os.geteuid() == 0 or sys.argv[1:] not in ([], ["--execute-reviewed"]):
        raise ValueError("driver_invocation_refused")
    execute = sys.argv[1:] == ["--execute-reviewed"]
    source = read_closed(SOURCE, 262144)
    envelope = read_closed(INPUT + "/installer-envelope.private", 8 * 1024 * 1024)
    if digest(source) != SOURCE_SHA or digest(envelope) != ENVELOPE_SHA:
        raise ValueError("pinned_input_mismatch")
    decoded = json.loads(envelope)
    manifest = base64.b64decode(decoded["manifestBase64"], validate=True)
    payload = base64.b64decode(decoded["payloadBase64"], validate=True)
    if digest(manifest) != MANIFEST_SHA or digest(payload) != PAYLOAD_SHA or len(payload) != 4250978:
        raise ValueError("pinned_artifact_mismatch")
    proof = json.loads(read_closed(INPUT + "/installer-plan-result.json", 65536))
    if (proof.get("sourceDescriptorClosed") is not True
            or proof.get("protectedPaths") != PATHS
            or proof.get("manifestDigest") != "sha256:" + MANIFEST_SHA
            or proof.get("envelopeDigest") != "sha256:" + ENVELOPE_SHA
            or proof.get("payloadDigest") != "sha256:" + PAYLOAD_SHA):
        raise ValueError("go_generation_proof_mismatch")
    try:
        os.lstat(RELEASE)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("release_not_fresh")
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i",
            "PATH=" + ENV["PATH"], PYTHON, "-I", "-S", "-c",
            source.decode("utf-8"), "--install", "sha256:" + MANIFEST_SHA]
    capture = tempfile.mkdtemp(prefix="darwin-installer-root-driver.", dir=CACHE)
    os.chmod(capture, 0o700)
    if os.path.realpath(capture) != capture:
        raise ValueError("capture_not_canonical")
    plan = dict(argv=argv, environment=ENV, installerSourceSHA256=SOURCE_SHA,
                manifestSHA256=MANIFEST_SHA, envelopeSHA256=ENVELOPE_SHA,
                payloadSHA256=PAYLOAD_SHA, protectedPaths=PATHS,
                heldInputsClosed=True, goSourceDescriptorClosed=True,
                internalDeadlineSeconds=120, outerDeadlineSeconds=130,
                executionRequested=execute, executionApprovalNotConferredByDriver=True)
    record(capture + "/invocation.private.json", plan)
    print(capture, flush=True)
    if not execute:
        return 0
    # This branch must not be invoked until main approves this exact source and
    # the separate tool action. No password prompt or environment inheritance.
    started = time.monotonic()
    result = dict(timedOut=False, rootCompletionConfirmed=False)
    with open(capture + "/root.stdout.private", "xb") as stdout, open(
            capture + "/root.stderr.private", "xb") as stderr:
        os.chmod(stdout.name, 0o600)
        os.chmod(stderr.name, 0o600)
        child = subprocess.Popen(argv, env=ENV, stdin=subprocess.PIPE,
                                 stdout=stdout, stderr=stderr, shell=False)
        result["createdSudoProcessID"] = child.pid
        try:
            child.communicate(input=envelope, timeout=130)
            result.update(exitCode=child.returncode, rootCompletionConfirmed=True)
        except subprocess.TimeoutExpired:
            # The tool must keep this driver session alive and retain its
            # handle. Do not discard the created Popen owner or close its
            # captures while sudo may still own a running setup. The root
            # program's original deadline is not reset by these observations.
            result.update(timedOut=True, exitCode=None)
            if child.stdin is not None:
                try:
                    child.stdin.close()
                except (OSError, ValueError):
                    result["stdinCloseFailed"] = True

            def report_wait(message):
                try:
                    print(message, flush=True)
                except (OSError, ValueError):
                    result["progressOutputFailed"] = True

            report_wait("root_completion_unconfirmed; retain this tool session")
            while True:
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    report_wait("root_completion_still_unconfirmed")
                    continue
                result.update(exitCode=child.returncode, rootCompletionConfirmed=True)
                break
    result["elapsedSeconds"] = time.monotonic() - started
    result["installerSourceAfterSHA256"] = digest(read_closed(SOURCE, 262144))
    result["sourceStable"] = result["installerSourceAfterSHA256"] == SOURCE_SHA
    result["protectedLoaderQualified"] = False
    result["nativeProcessIdentityQualified"] = False
    # Raw receipts and zero exit both need independent review. No copy outcome
    # here qualifies the protected loader or authorizes running the fixture.
    record(capture + "/root-result.json", result)
    return 0 if result.get("exitCode") == 0 and not result["timedOut"] and result["sourceStable"] else 1


if __name__ == "__main__":
    sys.exit(main())
