"""Own one runtime frontend invocation without granting application access.

Installed adapters call startup with an explicit selection and worker context.
Nothing in this module writes to stdout, retries startup, or stops the shared host.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import selectors
import subprocess
import time

from hub.client_launch_selection import RetainedRuntime, SelectionError, _admit_runtime, _load_selection
from hub import native_descriptor_admission
from sdk.python.agentmux_contracts.validation import validate
from sdk.python.agentmux_contracts.wire import strict_loads


OUTPUT_LIMIT = 262144
STDERR_LIMIT = 16384


@dataclass
class Capture:
    output: bytes = field(default=b"", repr=False)
    returncode: int | None = None
    failure: str | None = None
    # Retain the exact unreaped child. The adapter must finish cleanup before retry.
    pending: object = field(default=None, repr=False)
    readers: object = field(default=None, repr=False)
    streams: list = field(default_factory=list, repr=False)
    admission: RetainedRuntime | None = field(default=None, repr=False)

    def close_admission(self):
        if (self.pending is None and self.readers is None and not self.streams
                and self.admission is not None and not self.admission.closed):
            try:
                self.admission.close()
            except OSError:
                self.failure = "runtime_cleanup_failed"

    def close_streams(self):
        for stream in list(self.streams):
            try:
                stream.close()
            except OSError:
                self.failure = "runtime_cleanup_failed"
                # Python reports a consumed close through .closed. Do not retry
                # a consumed descriptor; retain an uncertain handle for inspection.
                if stream.closed is not True:
                    continue
            self.streams.remove(stream)

    def finish_cleanup(self):
        if self.readers is not None:
            self.readers.close()
            self.readers = None
        for stream in list(self.streams):
            if stream.closed is True:
                self.streams.remove(stream)
            elif stream.closed is False:
                try:
                    stream.close()
                    self.streams.remove(stream)
                except OSError:
                    pass
        if self.pending is not None:
            try:
                if self.pending.poll() is None:
                    self.pending.kill()
                self.returncode = self.pending.wait(timeout=1)
            except (subprocess.TimeoutExpired, OSError):
                return False
            self.pending = None
        self.close_admission()
        return not self.streams and (self.admission is None or self.admission.closed)


def invoke(arguments, *, budget, admission: RetainedRuntime):
    """Production process boundary; injected process facilities are test-only."""
    return _invoke_runtime(arguments, budget=budget, admission=admission)


def _invoke_runtime(arguments, *, budget, admission: RetainedRuntime, popen=subprocess.Popen, clock=time.monotonic,
           selector_factory=selectors.DefaultSelector):
    capture = Capture(admission=admission)
    try:
        return _invoke(arguments, budget=budget, popen=popen, clock=clock,
                       selector_factory=selector_factory, capture=capture)
    except BaseException:
        # Cancellation can arrive during cleanup too. The exact process and
        # reader owners remain reachable through the returned capture.
        capture.failure = "runtime_cancelled"
        return capture


def _invoke(arguments, *, budget, popen, clock, selector_factory, capture):
    """Drain both streams with caps, then reap the same child within a cleanup budget.

    The native frontend has its own 10s ensure/5s status budget. We allow one
    additional second for its final output, then at most one second for cleanup.
    An OS-level failure to reap is returned with ownership, never abandoned.
    """
    child = None
    readers = None
    streams_owned = False
    deadline = clock() + budget
    chunks = []
    sizes = {"out": 0, "err": 0}
    try:
        if (capture.admission is None or not arguments or arguments[0] != capture.admission.path
                or budget <= 0 or clock() >= deadline):
            raise SelectionError("launcher_unavailable")
        capture.admission.recheck(deadline=deadline)
        if clock() >= deadline:
            raise SelectionError("selection_deadline")
        child = popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, shell=False, start_new_session=True)
        capture.pending = child
        capture.streams = [stream for stream in (child.stdout, child.stderr) if stream is not None]
        streams_owned = True
        readers = selector_factory()
        capture.readers = readers
        for stream, name in ((child.stdout, "out"), (child.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            readers.register(stream, selectors.EVENT_READ, name)
        while readers.get_map() or child.poll() is None:
            remaining = deadline - clock()
            if remaining <= 0:
                capture.failure = "runtime_deadline"
                break
            for key, _ in readers.select(min(remaining, 0.05)):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    readers.unregister(key.fileobj)
                    continue
                name = key.data
                sizes[name] += len(block)
                if sizes[name] > (OUTPUT_LIMIT if name == "out" else STDERR_LIMIT):
                    capture.failure = "runtime_output_limit"
                    break
                if name == "out":
                    chunks.append(block)
            if capture.failure:
                break
        capture.output = b"".join(chunks)
    except KeyboardInterrupt:
        capture.failure = "runtime_cancelled"
    except SelectionError:
        capture.failure = "launcher_unavailable"
    except (OSError, ValueError):
        capture.failure = "runtime_unavailable"
    finally:
        if readers is not None:
            try:
                readers.close()
                capture.readers = None
            except OSError:
                capture.failure = "runtime_cleanup_failed"
        if child is not None:
            if not streams_owned:
                capture.streams = [stream for stream in (child.stdout, child.stderr) if stream is not None]
            # No output-reader threads remain. Close inherited pipes rather than
            # waiting for an unrelated descendant to close them.
            capture.close_streams()
            try:
                if child.poll() is None:
                    child.terminate()
                capture.returncode = child.wait(timeout=0.5)
                capture.pending = None
            except subprocess.TimeoutExpired:
                try:
                    child.kill()
                    capture.returncode = child.wait(timeout=0.5)
                    capture.pending = None
                except (subprocess.TimeoutExpired, OSError):
                    capture.failure = "runtime_cleanup_pending"
                    capture.pending = child
            except OSError:
                capture.failure = "runtime_cleanup_pending"
                capture.pending = child
        capture.close_admission()
    return capture


@dataclass
class StartupResult:
    public: dict
    capture: Capture | None = field(default=None, repr=False)
    selection_cleanup: object = field(default=None, repr=False)
    selection: object = field(default=None, repr=False)

    def finish_cleanup(self):
        process_done = self.capture is None or self.capture.finish_cleanup()
        selection_done = self.selection_cleanup is None or self.selection_cleanup.finish_cleanup()
        return process_done and selection_done


def result(operation, outcome, code=None):
    return StartupResult({"schemaVersion": "1.0.0", "kind": "client-startup",
                          "operation": operation, "outcome": outcome, "code": code,
                          "infrastructureReadiness": "unknown", "disposition": None,
                          "instanceId": None, "profileId": None, "callerIdentityOwnerHubId": None,
                          "applicationAccess": "unavailable", "dashboard": None})


def startup(selection_path, *, managed_worker, registered_context=None):
    """Production entrypoint: native admission and process ownership are fixed."""
    return _startup(selection_path, managed_worker=managed_worker,
                    descriptor_admission=native_descriptor_admission.check_descriptor, runner=invoke,
                    registered_context=registered_context)


def _startup(selection_path, *, managed_worker, descriptor_admission=None, runner=invoke, registered_context=None):
    """Called once by the installed adapter, not by MCP tool dispatch.

    managed_worker comes from the managed launch owner, not hook payloads or
    truthy environment strings. It suppresses bootstrap; it grants no authority.
    The injected runner is a test seam, never loaded from user configuration.
    """
    if type(managed_worker) is not bool:
        return result(None, "failed", "worker_context_invalid")
    operation = "status" if managed_worker else "ensure"
    entered = time.monotonic()
    try:
        selected = _load_selection(selection_path, descriptor_admission=descriptor_admission, deadline=entered + 1,
                                   registered_context=registered_context)
        admitted = _admit_runtime(descriptor_admission=descriptor_admission, deadline=entered + 1)
    except SelectionError as exc:
        code = str(exc)
        if code not in {"setup_required", "selection_invalid", "selection_permissions", "selection_deadline",
                        "selection_inside_workspace", "native_admission_required", "native_admission_failed", "launcher_unavailable",
                        "selection_cleanup_pending"}:
            code = "selection_invalid"
        out = result(operation, "setup_required" if code == "setup_required" else "failed", code)
        out.selection_cleanup = exc.cleanup
        return out
    try:
        capture = runner(selected.invocation.arguments(managed_worker=managed_worker), admission=admitted,
                         budget=max(0, (6 if managed_worker else 11) - (time.monotonic() - entered)))
    except BaseException:
        capture = Capture(failure="runtime_cancelled", admission=admitted)
    out = result(operation, "failed", capture.failure or "runtime_failed")
    out.capture = capture
    out.selection = selected
    if capture.failure or capture.returncode != 0:
        return out
    try:
        observation = strict_loads(capture.output)
        if type(observation) is dict and observation.get("kind") == "bootstrap-progress":
            if (operation != "ensure" or set(observation) != {
                    "schemaVersion", "kind", "requestDisposition", "instanceState", "receipt",
                    "detailsAvailable", "message"} or observation["schemaVersion"] != "1.0.0"
                    or observation["instanceState"] != "unknown"
                    or observation["detailsAvailable"] is not False
                    or observation["requestDisposition"] != "accepted"
                    or type(observation["receipt"]) is not dict
                    or observation["receipt"].get("kind") != "bootstrap-control-receipt"
                    or observation["receipt"].get("schemaVersion") != "1.0.0"
                    or observation["receipt"].get("outcome") != "accepted"):
                raise ValueError("receipt_invalid")
            # Receipt contents cannot establish current identity or readiness.
            out.public.update(outcome="progress", code="observation_unavailable")
            return out
        validate("startup-status-observation", observation)
        instance = observation["instance"]
        hub = observation["caller"]["authenticatedIdentityRef"]["ownerHubId"]
        if (instance["instanceId"], instance["profileId"]) != (
                selected.instance_id, selected.profile_id):
            out.public["code"] = "runtime_selection_mismatch"
            return out
        observed = datetime.fromisoformat(observation["observedAt"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - observed).total_seconds()
        if not 0 <= age <= 10:
            out.public["code"] = "runtime_observation_stale"
            return out
        out.public.update(outcome="observed", code=None, disposition=observation["disposition"],
                          infrastructureReadiness=instance["readiness"],
                          instanceId=selected.instance_id, profileId=selected.profile_id,
                          callerIdentityOwnerHubId=hub)
    except (ValueError, TypeError, KeyError, OverflowError):
        out.public["code"] = "runtime_output_invalid"
    return out


def human_summary(started):
    """Return text for the adapter's human channel; never write protocol stdout."""
    status = started.public
    if status["outcome"] == "observed":
        binding = status.get('applicationBinding', {})
        if binding.get('state') == 'verified':
            return (f"Instance {status['instanceId']}: {status['infrastructureReadiness']}. "
                    f"Authenticated hub {binding['hubId']}. Application commands and dashboard unavailable.")
        return (f"Instance {status['instanceId']}: "
                f"{status['infrastructureReadiness']}. Application access and dashboard unavailable.")
    if status["outcome"] == "setup_required":
        return "Agentmux setup required: select an enrolled profile before starting this client."
    if status["outcome"] == "progress":
        return "Agentmux startup observation unavailable. Application access and dashboard unavailable."
    return "Agentmux startup failed. Check the enrolled selection and runtime doctor."
