"""Caller-chain controls; mocked cases do not qualify native startup."""
import os
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from unittest.mock import Mock

from native_security.core_caller import (
    NativeCallerProbe, CallerEvidenceUnavailable, ProcessObservation,
)


class CoreCallerBoundaries(unittest.TestCase):
    def setUp(self):
        self.probe = object.__new__(NativeCallerProbe)
        self.rows = {21: ProcessObservation(21, 20, os.getuid(), (100, 1), '/selected/python'),
            20: ProcessObservation(20, 1, os.getuid(), (90, 1), '/selected/operator'),
            1: ProcessObservation(1, 0, 0, (1, 0), '/sbin/launchd')}

    def observe(self):
        return self.probe.observe(21,
            tmux_image='/selected/tmux', deadline=time.monotonic()+1)

    def test_complete_known_operator(self):
        with patch.object(self.probe, 'read', side_effect=lambda pid, deadline: self.rows[pid]):
            self.assertFalse(self.observe().in_pane)

    def test_tmux_ancestor_is_not_operator(self):
        self.rows[20] = ProcessObservation(20, 1, os.getuid(), (90, 1), '/selected/tmux')
        with patch.object(self.probe, 'read', side_effect=lambda pid, deadline: self.rows[pid]):
            self.assertTrue(self.observe().in_pane)

    def test_readable_non_tool_parent_preserves_complete_ancestry(self):
        self.rows[20] = ProcessObservation(20, 1, os.getuid(), (90, 1), '/Applications/Example.app/Contents/MacOS/Example')
        with patch.object(self.probe, 'read', side_effect=lambda pid, deadline: self.rows[pid]):
            proof = self.observe()
            self.assertFalse(proof.in_pane)
            self.assertEqual(proof.processes, (self.rows[21], self.rows[20]))

    def test_unreadable_parent_refuses(self):
        with patch.object(self.probe, 'read', side_effect=[self.rows[21], CallerEvidenceUnavailable()]):
            with self.assertRaises(CallerEvidenceUnavailable): self.observe()

    def test_other_user_and_loop_refuse(self):
        for parent, uid in ((1, os.getuid()+1), (21, os.getuid())):
            with self.subTest(parent=parent, uid=uid):
                self.rows[20] = ProcessObservation(20, parent, uid, (90, 1), '/parent')
                with patch.object(self.probe, 'read', side_effect=lambda pid, deadline: self.rows[pid]):
                    with self.assertRaises(CallerEvidenceUnavailable): self.observe()

    def test_changed_generation_refuses(self):
        changed = ProcessObservation(21, 20, os.getuid(), (101, 1), '/selected/python')
        with patch.object(self.probe, 'read', side_effect=[self.rows[21], self.rows[20], changed]):
            with self.assertRaises(CallerEvidenceUnavailable): self.observe()

    def test_incomplete_chain_refuses(self):
        self.rows[20] = ProcessObservation(20, 0, os.getuid(), (90, 1), '/selected/operator')
        with patch.object(self.probe, 'read', side_effect=lambda pid, deadline: self.rows[pid]):
            with self.assertRaises(CallerEvidenceUnavailable): self.observe()


@unittest.skipUnless(os.uname().sysname == 'Darwin', 'native macOS observation')
class NativeCoreCallerRead(unittest.TestCase):
    def test_current_process_observation_is_stable(self):
        probe = NativeCallerProbe()
        observed = probe.read(os.getpid(), time.monotonic()+2)
        self.assertEqual(observed.pid, os.getpid())
        self.assertEqual(observed.parent, os.getppid())
        self.assertEqual(observed.uid, os.getuid())
        self.assertTrue(observed.image.startswith('/'))


class NativeCoreHubCaller(unittest.TestCase):
    def setUp(self):
        from hub.server import Hub
        from hub.native_core_context import NativeCoreContext
        self.hub = object.__new__(Hub)
        self.hub.tp = SimpleNamespace(socket='owned-test')
        self.hub.store = SimpleNamespace(agents=Mock(return_value=[]))
        self.context = object.__new__(NativeCoreContext)
        self.hub._native_core = self.context
        self.proof = SimpleNamespace(processes=(ProcessObservation(21, 1, os.getuid(), (100, 1), '/selected/python'),), in_pane=False)

    def test_registered_worker_is_preserved(self):
        self.hub.store.agents.return_value = [{'pane_pid': 21, 'session': 'repo-worker-one'}]
        with patch.object(self.context, 'caller', return_value=self.proof), patch.object(self.context, 'tmux') as tmux:
            self.assertEqual(self.hub.identify_qualified(21), ('repo-worker-one', True))
            tmux.assert_not_called()

    def test_unregistered_pane_does_not_become_operator(self):
        self.proof.in_pane = True
        with patch.object(self.context, 'caller', return_value=self.proof), patch.object(self.context, 'tmux') as tmux:
            self.assertEqual(self.hub.identify(21), (None, True))
            tmux.assert_not_called()

    def test_proved_operator_and_absent_transport_are_separate(self):
        with patch.object(self.context, 'caller', return_value=self.proof), \
                patch.object(self.context, 'tmux', return_value=SimpleNamespace(returncode=1, stdout=b'')), \
                patch.object(self.context, 'transport_not_connectable', return_value=True):
            self.assertEqual(self.hub.identify_qualified(21), (None, False))

    def test_generic_transport_failure_with_present_socket_refuses(self):
        from hub.server import CallerClassificationUnavailable
        with patch.object(self.context, 'caller', return_value=self.proof), \
                patch.object(self.context, 'tmux', return_value=SimpleNamespace(returncode=1, stdout=b'')), \
                patch.object(self.context, 'transport_not_connectable', return_value=False):
            with self.assertRaises(CallerClassificationUnavailable): self.hub.identify_qualified(21)

    def test_warm_pane_inventory_still_refuses_operator(self):
        with patch.object(self.context, 'caller', return_value=self.proof), \
                patch.object(self.context, 'tmux', return_value=SimpleNamespace(returncode=0, stdout=b'21\n')):
            self.assertEqual(self.hub.identify_qualified(21), (None, True))

    def test_missing_tool_is_not_cold_authority(self):
        from hub.server import CallerClassificationUnavailable
        with patch.object(self.context, 'caller', return_value=self.proof), \
                patch.object(self.context, 'tmux', side_effect=FileNotFoundError), \
                patch.object(self.context, 'transport_not_connectable', return_value=True) as absent:
            with self.assertRaises(CallerClassificationUnavailable): self.hub.identify_qualified(21)
            absent.assert_not_called()
