"""Pinned setup for exactly two test-only artifact groups. No execution approval.

Default records both plans. --execute-reviewed accepts exactly one fixed group
and requires separate main review and user authorization. Never run as root.
"""
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time

SOURCE_ROOT = "/Users/ryan/GitHub/agentmux/platform/launcher/testdata/"
INPUT_ROOT = "/Users/ryan/.cache/agentmux-governance/darwin-test-sdk265-envelopes.tk7nhkl6/"
CACHE = "/Users/ryan/.cache/agentmux-governance"
PYTHON = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
PINS = {
    "darwin_test_artifact_installer.py": "df6d7b8d8d7fd1273bdf5d6c02c1f372569cba0f482ee087d2844fcbc36d6762",
    "darwin_protected_installer.py": "0d74190d6be9f1eb65b54ba49b87a547641b11fdd8f95073489f31874959708f"}
COMPOSED = "ba2fef3589f9b206e42bf2de587299d584fa7719eb0623bf52defaba4a6d9ded"
BASE = "/Library/Application Support/Agentmux/Protected/releases/"
INPUT_CAP = 11 * 1024 * 1024
GROUPS = {
    "runtime-fixture": {
        "plan": "f392af55f93ff4bfc6ec8fe3b920e284a83f01f1090b7722c06f0cd29a4ac4f8",
        "envelope": "050510ed726179a6226cfcb0b07d5b2f84d7c6f5e8469656f31423706dd6479e",
        "root": BASE + "c6831958218ddcc5b69c9753c4180272611faccc65da201a8298ba9e81bbce2e",
        "purpose": "native_runtime_five_member_test_artifact_only",
        "names": ["runtime-fixture", "bin/boot", "bin/kernel-lifecycle", "bin/internal-communication", "bin/exported-status"]},
    "frontend-receipt": {
        "plan": "095d1f5bd3528edd30289dbeb3aca13eaee25bd5012df2ed17604e4951235c2b",
        "envelope": "b6709c286eb0ce48581b520e957fc18930afdf4eb0fbcf12d251527b3eb1f39a",
        "root": BASE + "e3e04d6f8e9a0cdea412928ebef4d0b28f614c6fb7ac9df471fa6ed372d1145d",
        "purpose": "native_frontend_receipt_one_member_test_artifact_only",
        "names": ["agentmux-frontend-receipt-fixture"]}}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def held(path, cap, pin, ledger):
    entry = dict(path=path, closeAttempted=False, closeSucceeded=False)
    ledger.append(entry)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= cap):
            raise ValueError("input_metadata_refused")
        chunks, count = [], 0
        while True:
            block = os.read(fd, min(65536, cap + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            if count > cap:
                raise ValueError("input_bounds")
        data = b"".join(chunks)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, k) != getattr(after, k) for k in fields)
                or len(data) != before.st_size or sha(data) != pin):
            raise ValueError("pinned_input_changed")
        entry.update(sha256=pin, bytes=len(data), uid=before.st_uid,
                     mode=format(stat.S_IMODE(before.st_mode), "04o"),
                     device=before.st_dev, inode=before.st_ino, stable=True)
    finally:
        entry["closeAttempted"] = True
        os.close(fd)
        entry["closeSucceeded"] = True
    return data


def record(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(value, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())


def own_child(argv, envelope, stdout, stderr, factory=subprocess.Popen, report=print):
    """Retain the created object and captures until its sole wait confirms exit."""
    result = dict(timedOut=False, cancelled=False, rootCompletionConfirmed=False,
                  stdinCloseFailed=False, progressOutputFailed=False, parentIOFailed=False)

    def cancel(signum, frame):
        result["cancelled"] = True
        result["cancelSignal"] = "SIGINT" if signum == signal.SIGINT else "SIGTERM"

    # Installed before creation, non-raising through join and final receipt.
    # No signal is sent to the child and the original deadline is never reset.
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)

    if result["cancelled"]:
        result.update(processCreated=False, exitCode=None,
                      errorCode="parent_cancelled_before_creation")
        return result

    def report_wait(message):
        try:
            report(message, flush=True)
        except (OSError, ValueError):
            result["progressOutputFailed"] = True

    child = factory(argv, env=ENV, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, shell=False)
    result["processCreated"] = True
    result["createdSudoProcessID"] = child.pid  # Diagnostic only, never authority.
    try:
        child.communicate(input=envelope, timeout=130)
        result.update(exitCode=child.returncode, rootCompletionConfirmed=True)
    except subprocess.TimeoutExpired:
        result["timedOut"] = True
    except (OSError, ValueError):
        result["parentIOFailed"] = True
    if not result["rootCompletionConfirmed"]:
        if child.stdin is not None:
            try:
                child.stdin.close()
            except (OSError, ValueError):
                result["stdinCloseFailed"] = True
        report_wait("root_completion_unconfirmed; retain this tool session")
        while True:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                report_wait("root_completion_still_unconfirmed")
                continue
            except (OSError, ValueError):
                # Do not discard the owner on an unconfirmed wait failure.
                result["parentIOFailed"] = True
                report_wait("root_wait_failed_unconfirmed; retain this tool session")
                continue
            result.update(exitCode=child.returncode, rootCompletionConfirmed=True)
            break
    return result


def passed(result):
    return (result.get("exitCode") == 0 and result["rootCompletionConfirmed"]
            and not any(result[k] for k in ("timedOut", "cancelled", "stdinCloseFailed",
                                            "progressOutputFailed", "parentIOFailed")))


def controls():
    # No Popen, sudo, installed artifact, or external process is invoked.
    rows = []
    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        for scenario in ("normal", "timeout", "broken-stdin-progress", "cancel-int", "cancel-term",
                         "pre-cancel-int", "pre-cancel-term"):
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                class Input:
                    def close(self):
                        if scenario == "broken-stdin-progress":
                            raise OSError("control")

                class Child:
                    pid, returncode, stdin, observations = 0, None, Input(), 0

                    def communicate(self, input, timeout):
                        assert input == b"control" and timeout == 130
                        assert not stdout.closed and not stderr.closed
                        if scenario.startswith("cancel"):
                            sig = signal.SIGINT if scenario == "cancel-int" else signal.SIGTERM
                            signal.getsignal(sig)(sig, None)
                        if scenario in ("timeout", "broken-stdin-progress"):
                            raise subprocess.TimeoutExpired("control", 130)
                        self.returncode = 0

                    def wait(self, timeout):
                        assert timeout == 5 and not stdout.closed and not stderr.closed
                        self.observations += 1
                        if self.observations <= 2:
                            raise subprocess.TimeoutExpired("control", 5)
                        self.returncode = 0
                        return 0

                child = Child()
                factory_calls = []

                def factory(*args, **kwargs):
                    factory_calls.append(True)
                    assert kwargs["shell"] is False and kwargs["env"] == ENV
                    return child

                def report(*args, **kwargs):
                    if scenario == "broken-stdin-progress":
                        raise ValueError("control")

                real_signal = signal.signal

                def install_and_cancel(sig, handler):
                    old = real_signal(sig, handler)
                    target = signal.SIGINT if scenario == "pre-cancel-int" else signal.SIGTERM
                    if scenario.startswith("pre-cancel") and sig == target:
                        handler(sig, None)
                    return old

                signal.signal = install_and_cancel
                try:
                    result = own_child([], b"control", stdout, stderr, factory, report)
                finally:
                    signal.signal = real_signal
                if scenario.startswith("pre-cancel"):
                    assert not factory_calls and result["processCreated"] is False
                    assert result["rootCompletionConfirmed"] is False and result["exitCode"] is None
                    assert result["errorCode"] == "parent_cancelled_before_creation" and not passed(result)
                else:
                    assert factory_calls == [True] and result["rootCompletionConfirmed"]
                    assert passed(result) == (scenario == "normal")
                if scenario == "broken-stdin-progress":
                    assert result["stdinCloseFailed"] and result["progressOutputFailed"]
                if scenario in ("timeout", "broken-stdin-progress"):
                    assert child.observations == 3 and result["timedOut"]
                rows.append(dict(name=scenario, passed=True, result=result))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return dict(controls=rows, subprocessesExecuted=False, rootActions=False)


def group_plan(group, execute):
    if INPUT_ROOT is None:
        raise ValueError("sdk265_envelope_review_pending")
    if group not in GROUPS:
        raise ValueError("unknown_test_artifact_group")
    spec, inputs = GROUPS[group], []
    for name, pin in PINS.items():
        held(SOURCE_ROOT + name, 262144, pin, inputs)
    code = held(INPUT_ROOT + "composed-source.private.py", 262144, COMPOSED, inputs)
    plan = json.loads(held(INPUT_ROOT + group + ".installation-plan.private.json", 65536, spec["plan"], inputs))
    envelope = held(INPUT_ROOT + group + ".envelope.private.json", INPUT_CAP, spec["envelope"], inputs)
    if (plan["group"] != group or plan["purpose"] != spec["purpose"] or plan["releaseDirectory"] != spec["root"]
            or [m["relativePath"] for m in plan["members"]] != spec["names"]):
        raise ValueError("fixed_test_artifact_plan_mismatch")
    try:
        os.lstat(spec["root"])
    except FileNotFoundError:
        pass
    else:
        raise ValueError("release_not_fresh")
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", "PATH=" + ENV["PATH"], PYTHON,
            "-I", "-S", "-c", code.decode(), "--install", group, "sha256:" + spec["plan"]]
    capture = tempfile.mkdtemp(prefix="darwin-test-artifact-root-driver." + group + ".", dir=CACHE)
    os.chmod(capture, 0o700)
    if os.path.realpath(capture) != capture:
        raise ValueError("capture_not_canonical")
    record(capture + "/invocation.private.json", dict(argv=argv, environment=ENV, group=group,
           purpose=spec["purpose"], sources=inputs, composedSHA256=COMPOSED,
           installationPlanSHA256=spec["plan"], envelopeSHA256=spec["envelope"],
           protectedPaths=[spec["root"] + "/" + n for n in spec["names"]],
           internalDeadlineSeconds=120, outerDeadlineSeconds=130,
           executionRequested=execute, executionApprovalNotConferredByDriver=True))
    print(capture, flush=True)
    if not execute:
        return 0
    started = time.monotonic()
    outfd = os.open(capture + "/root.stdout.private", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(outfd, "wb") as stdout:
        errfd = os.open(capture + "/root.stderr.private", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(errfd, "wb") as stderr:
            result = own_child(argv, envelope, stdout, stderr)
    result.update(elapsedSeconds=time.monotonic()-started, group=group, protectedLoaderQualified=False,
                  nativeProcessIdentityQualified=False, productionReleaseQualified=False)
    record(capture + "/root-result.json", result)
    return 0 if passed(result) else 1


def main():
    if os.getuid() == 0 or os.geteuid() == 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("ordinary_user_isolated_driver_required")
    if sys.argv[1:] == ["--self-test"]:
        print(json.dumps(controls(), sort_keys=True))
        return 0
    if not sys.argv[1:]:
        for group in ("runtime-fixture", "frontend-receipt"):
            group_plan(group, False)
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--execute-reviewed" and sys.argv[2] in GROUPS:
        return group_plan(sys.argv[2], True)
    raise ValueError("fixed_test_artifact_driver_arguments")


if __name__ == "__main__":
    sys.exit(main())

