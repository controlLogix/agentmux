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
        caller = ['probe-start', 'probe-return']
        value = record()
        observe, run, absent = self.cold(self.proof)
        with observe, run, absent, native_check_timing.recording(value):
            self.assertEqual(self.hub.identify_qualified(21), (None, False))
        # One full recheck brackets the classification on each side; the helper
        # rechecks inside it keep their cheap guards and do not re-hash.
        self.assertEqual(stages(value), ['identify-start', *recheck, *caller, 'caller-return', 'agents-return',
            'tmux-run-start', 'tmux-run-return', 'not-connectable-start', 'not-connectable-return',
            *caller, 'fresh-caller-return', 'identify-return', *recheck])
        self.assertLessEqual(len(value['samples']), native_check_timing.LIMIT)
        self.assertEqual(self.context.installed.recheck.call_count, 2)
        self.assertEqual(self.context.files[0].check.call_count, 2)
        remaining = [item['proofRemaining'] for item in value['samples']]
        self.assertEqual(remaining, sorted(remaining, reverse=True))

    def test_same_result_and_calls_without_a_record(self):
        observe, run, absent = self.cold(self.proof)
        with observe, run, absent:
            self.assertEqual(self.hub.identify_qualified(21), (None, False))
        self.assertEqual(self.context.installed.recheck.call_count, 2)

    def test_changed_fresh_proof_still_refuses_and_records_refusal(self):
        from hub.server import CallerClassificationUnavailable
        value = record()
        changed = SimpleNamespace(processes=self.proof.processes, in_pane=True)
        observe, run, absent = self.cold(changed)
        with observe, run, absent, native_check_timing.recording(value):
            with self.assertRaises(CallerClassificationUnavailable):
                self.hub.identify_qualified(21)
        self.assertEqual(stages(value)[-2:], ['fresh-caller-return', 'identify-refused'])


class ClassificationBracket(NativeCheckStages):
    """One full recheck on each side; the cheap guards still run inside."""
    def test_opening_or_closing_full_recheck_refuses_the_classification(self):
        from hub.server import CallerClassificationUnavailable
        from hub.native_core_context import NativeCoreError
        for failing in (0, 1):
            self.setUp()
            effects = [None, None]
            effects[failing] = NativeCoreError()
            self.context.installed.recheck.side_effect = effects
            observe, run, absent = self.cold(self.proof)
            with observe, run, absent, self.assertRaises(CallerClassificationUnavailable):
                self.hub.identify_qualified(21)

    def test_closed_context_or_changed_alias_inside_still_refuses(self):
        from hub.server import CallerClassificationUnavailable

        def close(*args, **kwargs):
            self.context.closed = True
            return self.proof
        for change in ('closed', 'alias'):
            self.setUp()
            if change == 'closed':
                observe = patch('native_security.core_caller.NativeCallerProbe.observe', side_effect=close)
            else:
                self.context.aliases = {'/selected/alias': None}
                exists = patch('os.path.lexists', return_value=True)
                observe = patch('native_security.core_caller.NativeCallerProbe.observe', return_value=self.proof)
                observe = _both(observe, exists)
            with observe, self.assertRaises(CallerClassificationUnavailable):
                self.hub.identify_qualified(21)
            self.assertEqual(self.context.installed.recheck.call_count, 1)

    def test_other_threads_keep_full_rechecks_and_the_bracket_is_released(self):
        import threading
        from hub.server import CallerClassificationUnavailable
        seen = []

        def other_thread(*args, **kwargs):
            before = self.context.installed.recheck.call_count
            thread = threading.Thread(target=lambda: self.context.recheck(deadline=time.monotonic() + 5))
            thread.start()
            thread.join()
            seen.append(self.context.installed.recheck.call_count - before)
            return self.proof
        observe = patch('native_security.core_caller.NativeCallerProbe.observe', side_effect=other_thread)
        _, run, absent = self.cold(self.proof)
        with observe, run, absent:
            self.assertEqual(self.hub.identify_qualified(21), (None, False))
        self.assertEqual(seen, [1, 1])
        self.assertEqual(self.context.installed.recheck.call_count, 4)

        changed = SimpleNamespace(processes=self.proof.processes, in_pane=True)
        observe, run, absent = self.cold(changed)
        with observe, run, absent, self.assertRaises(CallerClassificationUnavailable):
            self.hub.identify_qualified(21)
        count = self.context.installed.recheck.call_count
        self.context.recheck(deadline=time.monotonic() + 5)
        self.assertEqual(self.context.installed.recheck.call_count, count + 1)

    def test_early_returns_still_run_the_closing_full_recheck(self):
        from hub.server import CallerClassificationUnavailable
        from hub.native_core_context import NativeCoreError
        in_pane = SimpleNamespace(processes=self.proof.processes, in_pane=True)
        for proof, agents in ((self.proof, [{'pane_pid': 21, 'session': 'repo-worker-one'}]), (in_pane, [])):
            self.setUp()
            self.hub.store.agents.return_value = agents
            with patch('native_security.core_caller.NativeCallerProbe.observe', return_value=proof):
                self.assertIn(self.hub.identify_qualified(21), (('repo-worker-one', True), (None, True)))
            self.assertEqual(self.context.installed.recheck.call_count, 2)
            self.setUp()
            self.hub.store.agents.return_value = agents
            self.context.installed.recheck.side_effect = [None, NativeCoreError()]
            with patch('native_security.core_caller.NativeCallerProbe.observe', return_value=proof):
                with self.assertRaises(CallerClassificationUnavailable):
                    self.hub.identify_qualified(21)

    def test_a_thread_that_inherits_the_context_still_rehashes(self):
        import contextvars
        import threading
        with self.context.classification(deadline=time.monotonic() + 5):
            inherited = contextvars.copy_context()
            thread = threading.Thread(target=inherited.run,
                                      args=(lambda: self.context.recheck(deadline=time.monotonic() + 5),))
            thread.start()
            thread.join()
        self.assertEqual(self.context.installed.recheck.call_count, 3)

    def test_nested_classification_does_not_add_rechecks(self):
        with self.context.classification(deadline=time.monotonic() + 5):
            with self.context.classification(deadline=time.monotonic() + 5):
                self.context.recheck(deadline=time.monotonic() + 5)
        self.assertEqual(self.context.installed.recheck.call_count, 2)


class _both:
    def __init__(self, *managers):
        self.managers = managers

    def __enter__(self):
        for manager in self.managers:
            manager.__enter__()

    def __exit__(self, *exc):
        for manager in reversed(self.managers):
            manager.__exit__(*exc)


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
        self.assertEqual(set(value), {'refused', 'samples', 'request'})
        self.assertEqual(value['request'], [])
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


class RequestPhases(unittest.TestCase):
    """Phase samples before the final check use fixed names, stay bounded and keep no request."""
    def admitted(self):
        from hub.server import _AuthenticatedLocalRequest
        return _AuthenticatedLocalRequest('operator', 'operator', None, b'{"private":"body"}', 'digest',
                                          time.monotonic() + 5)

    def test_phases_belong_to_one_admitted_request_and_are_bounded(self):
        import contextvars
        proof, other = self.admitted(), self.admitted()

        def request():
            native_check_timing.start_request(proof)
            native_check_timing.request_sample('dispatch-start')
            native_check_timing.request_sample('not-a-phase')
            for _ in range(40):
                native_check_timing.request_sample('dispatch-return')
        contextvars.copy_context().run(request)
        samples = native_check_timing.request_samples(proof)
        self.assertEqual([item['stage'] for item in samples[:2]], ['admitted', 'dispatch-start'])
        self.assertEqual(len(samples), native_check_timing.REQUEST_LIMIT)
        self.assertEqual(set(samples[0]), {'stage', 'proofRemaining'})
        self.assertEqual(native_check_timing.request_samples(other), [])
        native_check_timing.request_sample('dispatch-start')

    def test_a_freed_request_leaves_nothing_behind(self):
        import contextvars
        import gc
        before = len(native_check_timing._requests)
        proof = self.admitted()
        contextvars.copy_context().run(native_check_timing.start_request, proof)
        self.assertEqual(len(native_check_timing._requests), before + 1)
        self.assertNotIn(proof, [value for record in native_check_timing._requests.values() for value in record.values()])
        del proof
        gc.collect()
        self.assertEqual(len(native_check_timing._requests), before)

    def test_current_request_samples_are_task_local(self):
        import contextvars
        proof = self.admitted()

        def request():
            native_check_timing.start_request(proof)
            native_check_timing.request_sample('work-exchange-start')
            native_check_timing.request_sample('work-exchange-refused')
            return native_check_timing.current_request_samples()
        stages = [item['stage'] for item in contextvars.copy_context().run(request)]
        self.assertEqual(stages, ['admitted', 'work-exchange-start', 'work-exchange-refused'])
        self.assertEqual(contextvars.Context().run(native_check_timing.current_request_samples), [])

    def test_broken_proof_never_escapes(self):
        import contextvars

        def broken():
            native_check_timing.start_request(SimpleNamespace())
            native_check_timing.request_sample('dispatch-start')
            native_check_timing.start_request(None)
        contextvars.copy_context().run(broken)
        self.assertEqual(native_check_timing.request_samples(None), [])

if __name__ == '__main__':
    unittest.main()
