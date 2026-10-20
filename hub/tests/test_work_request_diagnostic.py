"""Closed diagnostics preserve the original authenticated request refusal."""
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hub.server import Hub, HubError, _AuthenticatedLocalRequest, _work_request_refusal


class WorkRequestDiagnosticTests(unittest.TestCase):
    def admitted(self):
        return _AuthenticatedLocalRequest('operator', 'operator', None,
            b'private request', 'private digest', 2)

    def test_current_guards_report_distinct_closed_stages(self):
        for stage, times, classification in (
                ('current-before-expired', [3, 3], (None, False)),
                ('unix-identity-changed', [1, 1], ('private-agent', True)),
                ('current-after-expired', [1, 3, 3], (None, False))):
            with self.subTest(stage=stage):
                hub = SimpleNamespace(identify_qualified=Mock(return_value=classification))
                with patch('hub.server.time.monotonic', side_effect=times), \
                        patch('hub.server.log') as log:
                    with self.assertRaises(HubError) as caught:
                        Hub._check_work_request_current(hub, (),
                            (self.admitted(), False, (12345, os.getuid())))
                self.assertEqual(str(caught.exception), 'authenticated work request changed or expired')
                diagnostic = json.loads(log.call_args.args[1])
                self.assertEqual(set(diagnostic), {'stage', 'proofRemaining'})
                self.assertEqual(diagnostic['stage'], stage)
                self.assertEqual(hub.identify_qualified.call_count,
                    0 if stage == 'current-before-expired' else 1)
                self.assertNotIn('private', log.call_args.args[1])
                self.assertNotIn('12345', log.call_args.args[1])

    def test_diagnostic_failure_preserves_public_refusal(self):
        with patch('hub.server.log', side_effect=RuntimeError('private logging error')):
            error = _work_request_refusal('current-before-expired', self.admitted())
        self.assertIs(type(error), HubError)
        self.assertEqual(str(error), 'authenticated work request changed or expired')

    def test_unknown_stage_and_nonfinite_time_do_not_leak(self):
        with patch('hub.server.time.monotonic', return_value=float('nan')), \
                patch('hub.server.log') as log:
            _work_request_refusal('private arbitrary text', self.admitted())
        self.assertEqual(json.loads(log.call_args.args[1]),
            {'stage': 'other', 'proofRemaining': None})
