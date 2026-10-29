"""Private native-check timing records stages only; it cannot change a classification."""
import math
import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hub import native_check_timing
from native_security.core_caller import ProcessObservation


def record(expires=None):
    return {'proof': SimpleNamespace(expires_monotonic=time.monotonic() + 5 if expires is None else expires),
            'samples': []}


def stages(value):
    return [item['stage'] for item in value['samples']]


class SampleBounds(unittest.TestCase):
    def test_nothing_is_recorded_outside_an_installed_record(self):
        native_check_timing.sample('identify-start')
        value = record()
        with native_check_timing.recording(value):
            native_check_timing.sample('identify-start')
        native_check_timing.sample('identify-return')
        self.assertEqual(stages(value), ['identify-start'])
        sample = value['samples'][0]
        self.assertEqual(set(sample), {'stage', 'proofRemaining'})
        self.assertTrue(0 < sample['proofRemaining'] <= 5)

    def test_unknown_stage_nonfinite_cap_and_broken_record_do_not_escape(self):
        value = record()
        with native_check_timing.recording(value):
            native_check_timing.sample('arbitrary private text')
            for _ in range(native_check_timing.LIMIT + 5):
                native_check_timing.sample('recheck-start')
        self.assertEqual(len(value['samples']), native_check_timing.LIMIT)
        self.assertNotIn('arbitrary private text', stages(value))
        infinite = record(math.inf)
        with native_check_timing.recording(infinite):
            native_check_timing.sample('recheck-start')
        self.assertEqual(infinite['samples'], [])
        with native_check_timing.recording({'proof': None}):
            native_check_timing.sample('recheck-start')

    def test_record_is_removed_when_the_check_raises(self):
        value = record()
        with self.assertRaises(RuntimeError), native_check_timing.recording(value):
            raise RuntimeError('original refusal')
        native_check_timing.sample('identify-start')
        self.assertEqual(value['samples'], [])


class NativeCheckStages(unittest.TestCase):
    def setUp(self):
        from hub.server import Hub
        from hub.native_core_context import NativeCoreContext
        self.hub = object.__new__(Hub)
        self.hub.tp = SimpleNamespace(socket='owned-test')
        self.hub.store = SimpleNamespace(agents=Mock(return_value=[]))
        self.context = object.__new__(NativeCoreContext)
        self.context.closed, self.context.pending, self.context.aliases = False, [], {}
        self.context.installed = SimpleNamespace(recheck=Mock())
        self.context.files = [SimpleNamespace(check=Mock())]
        self.context.tools = {'tmux': SimpleNamespace(path='/selected/tmux')}
        self.context.home = '/Users/selected'
        self.hub._native_core = self.context
        self.proof = SimpleNamespace(processes=(ProcessObservation(21, 1, os.getuid(), (100, 1), '/selected/python'),),
                                     in_pane=False)

    def cold(self, fresh):
        observe = Mock(side_effect=[self.proof, fresh])
        return (patch('native_security.core_caller.NativeCallerProbe.observe', observe),
                patch('subprocess.run', return_value=SimpleNamespace(returncode=1, stdout='')),
                patch.object(self.context, 'transport_not_connectable', return_value=True))

    def test_cold_path_samples_every_helper_without_changing_the_result(self):
        recheck = ['recheck-start', 'recheck-installed-return', 'recheck-return']
        caller = [*recheck, 'probe-start', 'probe-return', *recheck]
        value = record()
        observe, run, absent = self.cold(self.proof)
        with observe, run, absent, native_check_timing.recording(value):
            self.assertEqual(self.hub.identify_qualified(21), (None, False))
        self.assertEqual(stages(value), ['identify-start', *caller, 'caller-return', 'agents-return',
            *recheck, 'tmux-run-start', 'tmux-run-return', *recheck,
            'not-connectable-start', 'not-connectable-return', *caller, 'fresh-caller-return', 'identify-return'])
        self.assertLessEqual(len(value['samples']), native_check_timing.LIMIT)
        self.assertEqual(self.context.installed.recheck.call_count, 6)
        self.assertEqual(self.context.files[0].check.call_count, 6)
        remaining = [item['proofRemaining'] for item in value['samples']]
        self.assertEqual(remaining, sorted(remaining, reverse=True))

    def test_same_result_and_calls_without_a_record(self):
        observe, run, absent = self.cold(self.proof)
        with observe, run, absent:
            self.assertEqual(self.hub.identify_qualified(21), (None, False))
        self.assertEqual(self.context.installed.recheck.call_count, 6)

    def test_changed_fresh_proof_still_refuses_and_records_refusal(self):
        from hub.server import CallerClassificationUnavailable
        value = record()
        changed = SimpleNamespace(processes=self.proof.processes, in_pane=True)
        observe, run, absent = self.cold(changed)
        with observe, run, absent, native_check_timing.recording(value):
            with self.assertRaises(CallerClassificationUnavailable):
                self.hub.identify_qualified(21)
        self.assertEqual(stages(value)[-2:], ['fresh-caller-return', 'identify-refused'])


class OrdinaryWorkCheckTiming(unittest.TestCase):
    """Every caller of the current check logs a refused check's private timing once."""
    def setUp(self):
        from hub.server import Hub
        self.hub = object.__new__(Hub)
        self.identity = (SimpleNamespace(expires_monotonic=time.monotonic() + 5), False, (21, os.getuid()))

    def refuse(self, targets, identity):
        from hub.server import HubError
        native_check_timing.sample('identify-start')
        native_check_timing.sample('identify-refused')
        raise HubError('authenticated work request changed or expired')

    def test_refused_check_logs_fixed_stages_and_still_refuses(self):
        import json
        from hub.server import HubError
        self.hub._check_work_request_current_once = self.refuse
        with patch('hub.server.log') as log:
            with self.assertRaisesRegex(HubError, 'changed or expired'):
                self.hub._check_work_request_current((), self.identity)
        name, payload = log.call_args.args
        value = json.loads(payload)
        self.assertEqual(name, 'native check timing')
        self.assertEqual(set(value), {'refused', 'samples'})
        self.assertEqual([item['stage'] for item in value['samples']],
                         ['current-start', 'identify-start', 'identify-refused'])

    def test_passing_check_and_check_without_identity_log_nothing(self):
        once = Mock(return_value='current')
        self.hub._check_work_request_current_once = once
        with patch('hub.server.log') as log:
            self.assertEqual(self.hub._check_work_request_current((), self.identity), 'current')
            self.hub._check_work_request_current_once = self.refuse
            with self.assertRaises(Exception):
                self.hub._check_work_request_current((), None)
        log.assert_not_called()

    def test_kill_record_already_active_is_kept_and_not_logged_here(self):
        from hub.server import HubError
        self.hub._check_work_request_current_once = self.refuse
        outer = record()
        with patch('hub.server.log') as log, native_check_timing.recording(outer):
            with self.assertRaises(HubError):
                self.hub._check_work_request_current((), self.identity)
        log.assert_not_called()
        self.assertEqual(stages(outer), ['identify-start', 'identify-refused'])

    def test_a_broken_log_cannot_change_a_refusal(self):
        from hub.server import HubError
        self.hub._check_work_request_current_once = self.refuse
        with patch('hub.server.log', side_effect=OSError('log unavailable')):
            with self.assertRaisesRegex(HubError, 'changed or expired'):
                self.hub._check_work_request_current((), self.identity)

if __name__ == '__main__':
    unittest.main()
