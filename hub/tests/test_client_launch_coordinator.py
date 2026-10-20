"""Offline coordinator checks. Injected admission does not qualify native trust."""
import copy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hub import client_launch_coordinator as launch
from hub import client_launch_selection as selection
from hub import native_descriptor_admission as native
from hub.client_launch_selection import (_load_selection as load_selection, SelectionError, DescriptorPurpose, RuntimeAdmission)


class ClientLaunchCoordinator(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'selection with "quotes".json'
        self.document = {"schemaVersion": "1.0.0", "hostPolicy": str(self.root / "policy.json"),
                         "workspaces": [str(self.root / "project with spaces")],
                         "instanceId": "fixture_instance", "profileId": "fixture_profile",
                         "hubId": "fixture_hub"}
        self.write()
        self.admission = Mock(return_value=True)

    def write(self):
        self.path.write_text(json.dumps(self.document))
        self.path.chmod(0o600)

    def observation(self):
        vectors = Path(__file__).resolve().parents[2] / "tests/contracts/vectors/startup-status-examples.json"
        value = copy.deepcopy(json.loads(vectors.read_text())["examples"]["started"])
        value["observedAt"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return value

    def run_startup(self, capture, worker=False):
        runner = Mock(return_value=capture)
        with patch.object(launch, "_admit_runtime") as admit:
            out = launch._startup(str(self.path), managed_worker=worker,
                                 descriptor_admission=self.admission, runner=runner)
        admit.assert_called_once()
        self.assertIs(admit.call_args.kwargs["descriptor_admission"], self.admission)
        return out, runner

    def test_missing_selection_and_native_admission_fail_closed(self):
        runner = Mock()
        out = launch._startup(None, managed_worker=False, runner=runner)
        self.assertEqual(out.public["outcome"], "setup_required")
        out = launch._startup(str(self.path), managed_worker=False, runner=runner)
        self.assertEqual(out.public["code"], "native_admission_required")
        runner.assert_not_called()

    def test_uncertain_ancestor_close_retains_owner_and_never_retries(self):
        original_close = os.close
        calls = []
        def close(fd):
            calls.append(fd)
            original_close(fd)
            if len(calls) == 1:
                raise OSError("consumed close")
        runner = Mock()
        with patch.object(selection.os, "close", side_effect=close):
            observed = launch._startup(str(self.path), managed_worker=False,
                                       descriptor_admission=self.admission, runner=runner)
            self.assertEqual(observed.public["code"], "selection_cleanup_pending")
            self.assertFalse(observed.finish_cleanup())
            self.assertFalse(observed.finish_cleanup())
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0], calls[1])
        self.assertEqual(observed.selection_cleanup.uncertain, [calls[0]])
        runner.assert_not_called()

    def test_recheck_retains_uncertain_walk_close_and_never_spawns(self):
        fd = os.open(self.path, os.O_RDONLY)
        admitted = RuntimeAdmission(fd, str(self.path), self.admission)
        cleanup = selection.DescriptorCleanup()
        cleanup.uncertain.append(-1)  # Represents a consumed, never retried close.
        popen = Mock()
        with patch.object(selection, "_open_checked", side_effect=SelectionError(
                "selection_cleanup_pending", cleanup=cleanup)):
            capture = launch._invoke_runtime([str(self.path)], budget=1,
                                             admission=admitted, popen=popen)
        self.assertFalse(capture.finish_cleanup())
        self.assertFalse(admitted.closed)
        self.assertIs(admitted._walk_cleanup, cleanup)
        self.assertIsNone(admitted._fd)
        popen.assert_not_called()

    def test_public_selection_uses_exact_native_purposes(self):
        with patch.object(native, "check_descriptor", return_value=True) as check:
            selected = selection.load_selection(str(self.path))
        purposes = [call.kwargs["purpose"] for call in check.call_args_list]
        self.assertTrue(all(type(purpose) is native.DescriptorPurpose for purpose in purposes))
        self.assertIs(DescriptorPurpose, native.DescriptorPurpose)
        self.assertEqual(purposes[-2:], [native.DescriptorPurpose.PRIVATE_DIRECTORY,
                                        native.DescriptorPurpose.PRIVATE_FILE])
        self.assertTrue(all(purpose is native.DescriptorPurpose.PRIVATE_ANCESTOR for purpose in purposes[:-2]))
        self.assertEqual(selected.instance_id, "fixture_instance")

    def test_public_startup_normalizes_native_failure_and_never_spawns(self):
        with patch.object(native, "check_descriptor", side_effect=native.AdmissionError("PRIVATE_SENTINEL")), \
                patch.object(launch, "invoke") as run:
            out = launch.startup(str(self.path), managed_worker=False)
        self.assertEqual(out.public["code"], "native_admission_failed")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(out.public))
        run.assert_not_called()

    def test_public_entrypoints_reject_injected_admission(self):
        with self.assertRaises(TypeError):
            launch.startup(str(self.path), managed_worker=False, descriptor_admission=self.admission)
        with self.assertRaises(TypeError):
            selection.load_selection(str(self.path), descriptor_admission=self.admission)
        with self.assertRaises(TypeError):
            selection.admit_runtime(descriptor_admission=self.admission)

    def test_application_and_attestor_selection_are_explicit_and_outside_workspaces(self):
        self.document['application'] = {'clientKey': str(self.root / 'key.json'),
                                        'connection': str(self.root / 'connection.json'),
                                        'repositories': ['alpha', 'repo_2']}
        self.document['applicationAttestor'] = {'selection': str(self.root / 'attestor.json'),
                                               'sha256': 'sha256:' + 'a' * 64}
        self.write()
        selected = load_selection(str(self.path), descriptor_admission=self.admission)
        self.assertEqual(selected.application_client, self.document['application']['clientKey'])
        self.assertEqual(selected.application_repositories, ('alpha', 'repo_2'))
        self.assertIn('--application-attestor-selection', selected.invocation.arguments())
        self.assertNotIn('--application-attestor-selection', selected.invocation.arguments(managed_worker=True))
        for field in ('clientKey', 'connection'):
            previous = self.document['application'][field]
            self.document['application'][field] = self.document['workspaces'][0] + '/private.json'
            self.write()
            with self.assertRaises(SelectionError):
                load_selection(str(self.path), descriptor_admission=self.admission)
            self.document['application'][field] = previous
        for bad in (None, {}, {'selection': None, 'sha256': None}):
            self.document['applicationAttestor'] = bad
            self.write()
            with self.assertRaises(SelectionError):
                load_selection(str(self.path), descriptor_admission=self.admission)

    def test_application_repository_routes_are_optional_canonical_and_unique(self):
        base = {'clientKey': str(self.root / 'key.json'),
                'connection': str(self.root / 'connection.json')}
        self.document['application'] = base
        self.write()
        self.assertEqual(load_selection(str(self.path), descriptor_admission=self.admission)
                         .application_repositories, ())
        for repositories in ([], ['alpha', 'alpha'], ['Alpha'], ['alpha-one'], ['a' * 33],
                             'alpha', [None], [True]):
            self.document['application'] = {**base, 'repositories': repositories}
            self.write()
            with self.subTest(repositories=repositories), self.assertRaisesRegex(
                    SelectionError, '^selection_invalid$'):
                load_selection(str(self.path), descriptor_admission=self.admission)

    def services(self):
        return {'installationId': 'b' * 64, 'selection': str(self.root / "service 'quoted' $(literal).json"),
                'sha256': 'sha256:' + 'c' * 64}

    def with_services(self):
        self.document['applicationAttestor'] = {'selection': str(self.root / 'attestor.json'),
                                               'sha256': 'sha256:' + 'a' * 64}
        self.document['applicationServices'] = self.services()
        self.write()

    def test_service_selection_reaches_ensure_but_never_worker_status(self):
        self.with_services()
        for worker in (False, True):
            out, runner = self.run_startup(launch.Capture(b'{}', 1), worker=worker)
            args = runner.call_args.args[0]
            self.assertEqual(args[1], 'status' if worker else 'ensure')
            if worker:
                self.assertFalse(any(arg.startswith('--application-services') for arg in args))
                self.assertNotIn('--application-attestor-selection', args)
            else:
                self.assertEqual(args[-6:], ('--application-services-installation', 'b' * 64,
                    '--application-services-selection', self.services()['selection'],
                    '--application-services-selection-sha256', 'sha256:' + 'c' * 64))
            self.assertEqual(out.public['applicationAccess'], 'unavailable')

    def test_services_require_attestor_and_closed_complete_object(self):
        good = self.services()
        variants = [None, {}, [], True, {**good, 'unknown': 'PRIVATE'}]
        variants.append({**good, 'hostAccountPublicKey': 'STALE_HOST_FIELD'})
        variants.extend({key: value for key, value in good.items() if key != missing} for missing in good)
        variants.extend({**good, field: None} for field in good)
        variants.extend({**good, field: False} for field in good)
        variants.append({**good, 'selection': '//private/services.json'})
        for value in variants:
            self.with_services()
            self.document['applicationServices'] = value
            self.write()
            with self.subTest(value=value), self.assertRaisesRegex(SelectionError, '^selection_invalid$'):
                load_selection(str(self.path), descriptor_admission=self.admission)
        self.with_services()
        del self.document['applicationAttestor']
        self.write()
        with self.assertRaisesRegex(SelectionError, '^selection_invalid$'):
            load_selection(str(self.path), descriptor_admission=self.admission)

    def test_service_selection_cannot_be_inside_workspace_or_point_into_one(self):
        self.with_services()
        workspace = Path(self.document['workspaces'][0])
        workspace.mkdir()
        target = workspace / 'service.json'
        target.write_text('{}')
        linked = self.root / 'linked-service.json'
        linked.symlink_to(target)
        for selected in (str(target), str(linked)):
            self.document['applicationServices']['selection'] = selected
            self.write()
            with self.subTest(selected=selected), self.assertRaisesRegex(SelectionError, '^selection_inside_workspace$'):
                load_selection(str(self.path), descriptor_admission=self.admission)
        self.document['applicationServices']['selection'] = str(self.root / 'other-private-service.json')
        self.write()
        self.assertEqual(load_selection(str(self.path), descriptor_admission=self.admission)
                         .invocation.application_services_selection, str(self.root / 'other-private-service.json'))

    def test_private_selection_and_literal_arguments(self):
        selected = load_selection(str(self.path), descriptor_admission=self.admission)
        self.assertEqual(selected.invocation.workspaces, tuple(self.document["workspaces"]))
        self.assertTrue(any(call.kwargs["purpose"] == DescriptorPurpose.PRIVATE_FILE for call in self.admission.call_args_list))
        with patch.dict(os.environ, {"AGENTMUX_HOME": "/wrong", "AGENTMUX_HUB_URL": "tcp://wrong"}):
            out, runner = self.run_startup(launch.Capture(b"{}", 1), worker=True)
        args = runner.call_args.args[0]
        self.assertEqual(args[1], "status")
        self.assertEqual(args[-1], self.document["workspaces"][0])
        self.assertTrue(0 < runner.call_args.kwargs["budget"] <= 6)
        self.assertEqual(out.public["applicationAccess"], "unavailable")

    def test_non_boolean_worker_never_invokes_runtime(self):
        for worker in (None, "false", 1):
            runner = Mock()
            self.assertEqual(launch._startup(str(self.path), managed_worker=worker,
                                           runner=runner).public["code"], "worker_context_invalid")
            runner.assert_not_called()

    def test_unsafe_selection_modes_links_size_and_schema(self):
        for mutation in ("mode", "hardlink", "symlink", "large", "extra", "duplicate", "workspace"):
            with self.subTest(mutation=mutation):
                self.write()
                other = self.root / "other"
                if other.exists():
                    other.unlink()
                if mutation == "mode":
                    self.path.chmod(0o644)
                elif mutation == "hardlink":
                    os.link(self.path, other)
                elif mutation == "symlink":
                    self.path.rename(other)
                    self.path.symlink_to(other)
                elif mutation == "large":
                    self.path.write_bytes(b" " * 16385)
                elif mutation == "extra":
                    self.path.write_text(json.dumps({**self.document, "endpoint": "secret"}))
                elif mutation == "duplicate":
                    self.path.write_text('{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}')
                else:
                    self.path.write_text(json.dumps({**self.document, "workspaces": [str(self.root)]}))
                with self.assertRaises(SelectionError):
                    load_selection(str(self.path), descriptor_admission=self.admission)
                self.path.unlink()

    def test_admission_denial_prevents_runtime(self):
        def deny(fd, *, purpose, deadline):
            raise SelectionError("selection_permissions")
        runner = Mock()
        out = launch._startup(str(self.path), managed_worker=False, descriptor_admission=deny, runner=runner)
        self.assertEqual(out.public["code"], "selection_permissions")
        runner.assert_not_called()

    def test_false_admission_and_writable_parent_are_refused(self):
        with self.assertRaises(SelectionError):
            load_selection(str(self.path), descriptor_admission=lambda *a, **k: False)
        self.root.chmod(0o770)
        try:
            with self.assertRaises(SelectionError):
                load_selection(str(self.path), descriptor_admission=self.admission)
        finally:
            self.root.chmod(0o700)

    def test_observation_is_infrastructure_only_and_no_stdout(self):
        observation = self.observation()
        observation["instance"]["displayName"] = "PRIVATE_SENTINEL"
        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            out, runner = self.run_startup(launch.Capture(json.dumps(observation).encode(), 0))
            summary = launch.human_summary(out)
            self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(runner.call_args.args[0][1], "ensure")
        self.assertEqual(out.public["outcome"], "observed")
        self.assertEqual(out.public["applicationAccess"], "unavailable")
        self.assertIsNone(out.public["dashboard"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(out.public) + summary)
        self.assertNotIn("runtime hub", summary)

    def test_mismatch_stale_and_malformed_observations_are_refused(self):
        for change, code in (("mismatch", "runtime_selection_mismatch"),
                             ("stale", "runtime_observation_stale"),
                             ("malformed", "runtime_output_invalid")):
            observation = self.observation()
            if change == "mismatch":
                observation["instance"]["instanceId"] = "other_instance"
            elif change == "stale":
                observation["observedAt"] = "2020-01-01T00:00:00Z"
            else:
                observation = {"secret": "PRIVATE_SENTINEL"}
            out, _ = self.run_startup(launch.Capture(json.dumps(observation).encode(), 0))
            self.assertEqual(out.public["code"], code)
            self.assertIsNone(out.public["instanceId"])

    def test_receipt_never_grants_identity_or_readiness(self):
        receipt = {"schemaVersion": "1.0.0", "kind": "bootstrap-progress", "requestDisposition": "accepted",
                   "instanceState": "unknown", "detailsAvailable": False, "message": "private",
                   "receipt": {"schemaVersion": "1.0.0", "kind": "bootstrap-control-receipt", "outcome": "accepted"}}
        out, _ = self.run_startup(launch.Capture(json.dumps(receipt).encode(), 0))
        self.assertEqual(out.public["outcome"], "progress")
        self.assertIsNone(out.public["instanceId"])
        self.assertEqual(out.public["infrastructureReadiness"], "unknown")
        malformed, _ = self.run_startup(launch.Capture(b'{"kind":"bootstrap-progress"}', 0))
        self.assertEqual(malformed.public["code"], "runtime_output_invalid")


class RuntimeOwnership(unittest.TestCase):
    def admitted(self, path="/runtime"):
        admitted = Mock(path=path, closed=False)
        admitted.close.side_effect = lambda: setattr(admitted, "closed", True)
        return admitted

    def child(self):
        child = Mock()
        child.stdout.fileno.return_value = 91
        child.stderr.fileno.return_value = 92
        child.poll.return_value = 0
        child.wait.return_value = 0
        return child

    def test_one_child_literal_arguments_and_drained_output(self):
        child = self.child()
        selector = Mock()
        selector.get_map.side_effect = [{1: 1}, {}]
        selector.select.return_value = [(SimpleNamespace(fileobj=child.stdout, data="out"), 1)]
        start = Mock(return_value=child)
        with patch.object(launch.os, "set_blocking"), patch.object(launch.os, "read", return_value=b"{}"):
            captured = launch._invoke_runtime(("/literal runtime", "status", "a ' b"), budget=6,
                                     admission=self.admitted("/literal runtime"),
                                     popen=start, selector_factory=lambda: selector)
        self.assertEqual(captured.output, b"{}")
        self.assertIsNone(captured.pending)
        start.assert_called_once()
        self.assertFalse(start.call_args.kwargs["shell"])
        self.assertEqual(start.call_args.args[0][-1], "a ' b")
        child.wait.assert_called_once()
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_admission_stays_open_through_spawn_and_wait(self):
        child = self.child()
        admitted = self.admitted()
        sequence = []
        admitted.recheck.side_effect = lambda **kwargs: sequence.append("recheck")
        def start(*args, **kwargs):
            self.assertFalse(admitted.closed)
            sequence.append("spawn")
            return child
        def wait(**kwargs):
            self.assertFalse(admitted.closed)
            sequence.append("wait")
            return 0
        child.wait.side_effect = wait
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(launch.os, "set_blocking"):
            captured = launch._invoke_runtime(("/runtime", "status"), budget=6, admission=admitted,
                                     popen=start, selector_factory=lambda: selector)
        self.assertEqual(sequence, ["recheck", "spawn", "wait"])
        self.assertTrue(admitted.closed)
        self.assertIs(captured.admission, admitted)

    def test_failed_recheck_or_spent_budget_does_not_spawn(self):
        for mode in ("changed", "expired", "zero"):
            with self.subTest(mode=mode):
                admitted = self.admitted()
                start = Mock()
                if mode == "changed":
                    admitted.recheck.side_effect = SelectionError("launcher_unavailable")
                clock = Mock(side_effect=[0, 0, 7]) if mode == "expired" else time.monotonic
                captured = launch._invoke_runtime(("/runtime", "status"), budget=0 if mode == "zero" else 6,
                                         admission=admitted, popen=start, clock=clock)
                start.assert_not_called()
                self.assertEqual(captured.failure, "launcher_unavailable")
                self.assertTrue(admitted.closed)

    def test_deadline_keeps_original_child_when_cleanup_cannot_finish(self):
        child = self.child()
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("private", 1)
        selector = Mock()
        selector.get_map.return_value = {1: 1}
        ticks = iter((0, 0, 0, 7))
        admitted = self.admitted()
        with patch.object(launch.os, "set_blocking"):
            captured = launch._invoke_runtime(("/runtime", "status"), budget=6, admission=admitted, popen=lambda *a, **k: child,
                                     clock=lambda: next(ticks), selector_factory=lambda: selector)
        self.assertIs(captured.pending, child)
        self.assertFalse(admitted.closed)
        self.assertEqual(captured.failure, "runtime_cleanup_pending")
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        child.wait.side_effect = None
        child.wait.return_value = -9
        self.assertTrue(captured.finish_cleanup())
        self.assertIsNone(captured.pending)
        self.assertTrue(admitted.closed)


    def test_interrupt_during_wait_preserves_child(self):
        child = self.child()
        child.wait.side_effect = KeyboardInterrupt()
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(launch.os, "set_blocking"):
            captured = launch._invoke_runtime(("/runtime", "status"), budget=6, admission=self.admitted(), popen=lambda *a, **k: child,
                                     selector_factory=lambda: selector)
        self.assertIs(captured.pending, child)
        self.assertEqual(captured.failure, "runtime_cancelled")

    def test_output_limit_terminates_without_exposing_stderr(self):
        child = self.child()
        selector = Mock()
        selector.get_map.return_value = {1: 1}
        selector.select.return_value = [(SimpleNamespace(fileobj=child.stderr, data="err"), 1)]
        with patch.object(launch.os, "set_blocking"), patch.object(
                launch.os, "read", return_value=b"PRIVATE_SENTINEL" * 2000):
            captured = launch._invoke_runtime(("/runtime", "status"), budget=6, admission=self.admitted(), popen=lambda *a, **k: child,
                                     selector_factory=lambda: selector)
        self.assertEqual(captured.failure, "runtime_output_limit")
        self.assertEqual(captured.output, b"")
        child.wait.assert_called_once()

    def test_close_failure_still_reaps_original_child(self):
        child = self.child()
        child.stdout.closed = False
        child.stdout.close.side_effect = [OSError("PRIVATE_SENTINEL"), None]
        selector = Mock()
        selector.get_map.return_value = {}
        with patch.object(launch.os, "set_blocking"):
            captured = launch._invoke_runtime(("/runtime", "status"), budget=6, admission=self.admitted(), popen=lambda *a, **k: child,
                                     selector_factory=lambda: selector)
        self.assertEqual(captured.failure, "runtime_cleanup_failed")
        self.assertIsNone(captured.pending)
        child.wait.assert_called_once()
        child.stderr.close.assert_called_once()
        self.assertEqual(captured.streams, [child.stdout])
        self.assertTrue(captured.finish_cleanup())
        self.assertEqual(child.stdout.close.call_count, 2)


class RetainedExecutable(unittest.TestCase):
    def test_uncertain_close_remains_incomplete_without_descriptor_retry(self):
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno())
            admitted = RuntimeAdmission(fd, "/runtime", Mock(return_value=True))
            real_close = os.close
            def consumed_then_error(number):
                real_close(number)
                raise OSError("close disposition uncertain")
            captured = launch.Capture(admission=admitted)
            with patch("hub.client_launch_selection.os.close", side_effect=consumed_then_error) as close:
                captured.close_admission()
                self.assertFalse(captured.finish_cleanup())
                close.assert_called_once_with(fd)
            self.assertFalse(admitted.closed)
            self.assertEqual(captured.failure, "runtime_cleanup_failed")

    def test_recheck_close_failure_retains_uncertainty(self):
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno())
            admitted = RuntimeAdmission(fd, "/runtime", Mock(return_value=True))
            candidate = os.dup(fd)
            real_close = os.close
            def close(number):
                real_close(number)
                if number == candidate:
                    raise OSError("close disposition uncertain")
            with patch("hub.client_launch_selection._open_checked", return_value=candidate), patch(
                    "hub.client_launch_selection.os.close", side_effect=close) as closed:
                with self.assertRaises(OSError):
                    admitted.recheck(deadline=time.monotonic() + 1)
                captured = launch.Capture(admission=admitted)
                captured.close_admission()
                self.assertFalse(captured.finish_cleanup())
                self.assertEqual([call.args[0] for call in closed.call_args_list], [candidate, fd])

    def test_open_descriptor_is_retained_and_replacement_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime"
            path.write_bytes(b"original")
            fd = os.open(path, os.O_RDONLY)
            native = Mock(return_value=True)
            admitted = RuntimeAdmission(fd, str(path), native)
            try:
                with patch("hub.client_launch_selection._open_checked",
                           side_effect=lambda *a, **k: os.open(path, os.O_RDONLY)):
                    admitted.recheck(deadline=time.monotonic() + 1)
                    self.assertEqual(os.pread(fd, 8, 0), b"original")
                    replacement = Path(tmp) / "replacement"
                    replacement.write_bytes(b"original")
                    replacement.replace(path)
                    with self.assertRaises(SelectionError):
                        admitted.recheck(deadline=time.monotonic() + 1)
                self.assertEqual(native.call_args.kwargs["purpose"], DescriptorPurpose.PROTECTED_EXECUTABLE)
            finally:
                admitted.close()
            admitted.close()
            with self.assertRaises(OSError):
                os.fstat(fd)



if __name__ == "__main__":
    unittest.main()
