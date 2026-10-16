"""Unprivileged fixed APFS driver. Plans are not execution authorization.

Root receives held reviewed literal bytes, with no checkout imports or paths.
The retained parent owns its created process through terminal confirmation.
Four-release provisioning is deliberately separate.
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

SOURCE_ROOT = "/Users/ryan/GitHub/agentmux/platform/internal/darwinownershipfixture/testdata/apfs_mount/"
CACHE = "/Users/ryan/.cache/agentmux-governance"
PYTHON = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
NONCE = "20261015-7c4e92b1"
ROOT = "/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1"
PROGRAMS = {
    "setup": ("setup.py", "f96072677c2dbcf89dbb4aef6b901538d93f281ee9288fa922e81d813d8c3abc"),
    "teardown": ("teardown.py", "116e87a1abd76ec66c057d108dfab58dc194dd0d593d8c51dbfd20c096229d35")}
# Main must bind actual reviewed setup, inspector and every mount-test receipt.
# No caller attestation, environment variable or file discovery can enable this.
TEARDOWN_EVIDENCE = None
PARTIAL_RECOVERY_CONFIRMATION = None
PARTIAL_RECOVERY_REVIEW_PATH = "/Users/ryan/.cache/agentmux-governance/apfs-partial-detach-confirmation-4d927ca8.private.json"


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
        child.communicate(input=envelope, timeout=150)
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
                        assert input == b"control" and timeout == 150
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


def require_unmasked():
    current = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if current.intersection({signal.SIGINT, signal.SIGTERM}):
        raise ValueError("apfs_inherited_cancellation_mask_refused")


def teardown_input():
    # This candidate intentionally cannot attest to future process joins.
    # Replace only after main reviews and binds the actual complete evidence set.
    if TEARDOWN_EVIDENCE is None:
        raise ValueError("apfs_teardown_join_evidence_unbound")
    raise ValueError("apfs_teardown_evidence_schema_not_reviewed")


def partial_recovery_confirmation(inputs):
    binding = PARTIAL_RECOVERY_CONFIRMATION
    if binding is None:
        raise ValueError("partial_recovery_confirmation_unbound")
    if (type(binding) is not dict or set(binding) != {"sha256"}
            or type(binding["sha256"]) is not str or len(binding["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in binding["sha256"])):
        raise ValueError("partial_recovery_confirmation_pin_refused")
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("partial_recovery_confirmation_duplicate_key")
            result[key] = item
        return result
    raw = held(PARTIAL_RECOVERY_REVIEW_PATH, 65536, binding["sha256"], inputs)
    if inputs[-1]["mode"] != "0600":
        raise ValueError("partial_recovery_confirmation_mode_refused")
    actual = json.loads(raw, object_pairs_hook=pairs)
    expected = {"purpose": "reviewed_partial_normal_detach_confirmation", "nonce": "20261015-4d927ca8",
                "image": "/private/tmp/agentmux-c05-apfs-20261015-4d927ca8/owners.dmg",
                "rootParentJoined": True, "rootExit": 0, "partialNormalDetachComplete": True,
                "exactImageAbsent": True, "filesRetained": True,
                "historicalPerCommandWaitProof": "absent", "historicalDescendantCompletion": "unknown"}
    if (type(actual) is not dict or set(actual) != set(expected)
            or json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True)):
        raise ValueError("partial_recovery_confirmation_schema_refused")
    return binding["sha256"]


def invocation(action, execute):
    if action not in PROGRAMS:
        raise ValueError("fixed_apfs_action_required")
    name, pin = PROGRAMS[action]
    inputs = []
    code = held(SOURCE_ROOT + name, 262144, pin, inputs)
    recovery_pin = partial_recovery_confirmation(inputs) if execute else None
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/env", "-i", "PATH=" + ENV["PATH"],
            PYTHON, "-I", "-S", "-c", code.decode("utf-8")]
    # The root programs accept argv ["-c"] only. No target or nonce argument.
    capture = tempfile.mkdtemp(prefix="apfs-driver." + action + ".", dir=CACHE)
    os.chmod(capture, 0o700)
    if os.path.realpath(capture) != capture:
        raise ValueError("capture_not_canonical")
    record(capture + "/invocation.private.json", dict(action=action, argv=argv,
           environment=ENV, nonce=NONCE, fixedRoot=ROOT, programSHA256=pin, sources=inputs,
           rootOriginalDeadlineSeconds=120, parentInitialDeadlineSeconds=150,
           teardownEvidenceBound=False, partialRecoveryConfirmationSHA256=recovery_pin, executionRequested=execute,
           executionApprovalNotConferredByDriver=True))
    print(capture, flush=True)
    if not execute:
        return 0
    data = b"" if action == "setup" else teardown_input()
    require_unmasked()  # Refuse, never silently alter an inherited blocked mask.

    def fixed_factory(*args, **kwargs):
        # Recheck directly before creation. own_child has already installed its
        # non-raising handlers; no mask window or preexec hook affects the child.
        require_unmasked()
        return subprocess.Popen(*args, **kwargs)

    started = time.monotonic()
    outfd = os.open(capture + "/root.stdout.private", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(outfd, "wb") as stdout:
        errfd = os.open(capture + "/root.stderr.private", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(errfd, "wb") as stderr:
            result = own_child(argv, data, stdout, stderr, factory=fixed_factory)
    result.update(action=action, nonce=NONCE, elapsedSeconds=time.monotonic()-started,
                  rootReceiptRequiresIndependentReview=True, mountQualified=False)
    record(capture + "/root-result.json", result)
    return 0 if passed(result) else 1


def driver_controls():
    result = controls()
    try:
        teardown_input()
    except ValueError as error:
        assert str(error) == "apfs_teardown_join_evidence_unbound"
    else:
        raise AssertionError("unbound_teardown_false_acceptance")
    result["unboundTeardownRefused"] = True
    return result


def main():
    if os.getuid() == 0 or os.geteuid() == 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("ordinary_user_isolated_driver_required")
    if sys.argv[1:] == ["--self-test"]:
        print(json.dumps(driver_controls(), sort_keys=True))
        return 0
    if not sys.argv[1:]:
        invocation("setup", False)
        invocation("teardown", False)
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--execute-reviewed" and sys.argv[2] in PROGRAMS:
        return invocation(sys.argv[2], True)
    raise ValueError("fixed_apfs_driver_arguments")


if __name__ == "__main__":
    sys.exit(main())
