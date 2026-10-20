"""Private kill timing cannot grant authority or change an original result."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hub import server
from .test_kill_admission_turn import KillAdmissionTurnTests
from .test_work_source import SelectedWorkSourceFixture


class KillReplyTimingTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = KillAdmissionTurnTests.configure_channels
    asyncSetUp = KillAdmissionTurnTests.asyncSetUp
    join_tasks = KillAdmissionTurnTests.join_tasks
    task = KillAdmissionTurnTests.task
    gate = KillAdmissionTurnTests.gate
    framed_connection = KillAdmissionTurnTests.framed_connection
    registered = KillAdmissionTurnTests.registered
    prepare = KillAdmissionTurnTests.prepare
    cancelled_original = KillAdmissionTurnTests.cancelled_original

    async def test_cancelled_source_joins_before_timing_record_is_removed(self):
        await self.cancelled_original('source')
        self.assertFalse(self.hub._kill_reply_timings)

    async def test_cancelled_admission_db_joins_before_timing_record_is_removed(self):
        await self.cancelled_original('admit')
        self.assertFalse(self.hub._kill_reply_timings)

    async def test_same_id_replay_has_separate_bounded_private_records(self):
        request = await self.prepare()
        with patch.object(server, 'log') as log, \
                patch.object(self.hub, 'harness', return_value=True) as effect, \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as source, \
                patch.object(self.hub, 'identify_qualified', wraps=self.hub.identify_qualified) as identify:
            first = await self.framed_connection(request)
            second = await self.framed_connection(request)
            self.assertTrue(first['ok'], first)
            self.assertEqual(second, first)
            effect.assert_called_once()
            self.assertEqual(source.await_count, 2)
            self.assertEqual(identify.call_count, 4)
            records = [json.loads(call.args[1]) for call in log.call_args_list
                       if call.args[0] == 'kill reply timing']
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]['connection'], records[1]['connection'])
        for record in records:
            self.assertEqual(set(record), {'connection', 'samples'})
            self.assertEqual(len(record['connection']), 16)
            self.assertEqual([sample['stage'] for sample in record['samples']],
                ['late-source-start', 'late-source-return', 'dispatch-return', 'gate-request', 'maintenance-acquired', 'gate-acquired', 'db-submit', 'db-entry', 'check-return'])
            for sample in record['samples']:
                self.assertEqual(set(sample), {'stage', 'proofRemaining'})
                self.assertGreater(sample['proofRemaining'], 0)
                self.assertLessEqual(sample['proofRemaining'], 5)
            self.assertNotIn(request['operationId'], json.dumps(record))
            self.assertNotIn(request['args']['session'], json.dumps(record))
        self.assertFalse(self.hub._kill_reply_timings)

    async def test_logging_failure_preserves_success_and_clears_record(self):
        request = await self.prepare()
        with patch.object(server, 'log', side_effect=RuntimeError('unavailable diagnostic sink')), \
                patch.object(self.hub, 'harness', return_value=True) as effect:
            result = await self.framed_connection(request)
            self.assertTrue(result['ok'], result)
            effect.assert_called_once()
        self.assertFalse(self.hub._kill_reply_timings)

    async def test_final_check_refusal_is_preserved_and_record_released(self):
        request = await self.prepare()
        with patch.object(self.hub, '_check_work_request_current',
                side_effect=server.HubError('original current check refused')), \
                patch.object(self.hub, 'harness', return_value=True) as effect, \
                patch.object(server, 'log') as log:
            result = await self.framed_connection(request)
            self.assertEqual(result, {'ok': False, 'error': 'original current check refused'})
            effect.assert_called_once()
            records = [json.loads(call.args[1]) for call in log.call_args_list
                       if call.args[0] == 'kill reply timing']
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['samples'][-1]['stage'], 'check-refused')
        self.assertFalse(self.hub._kill_reply_timings)


class TimingSampleTests(unittest.TestCase):
    def test_sample_failure_nonfinite_and_cap_do_not_escape(self):
        record = {'proof': SimpleNamespace(expires_monotonic=float('inf')), 'samples': []}
        server._kill_reply_sample(record, 'db-entry')
        self.assertEqual(record['samples'], [])
        record['proof'] = SimpleNamespace(expires_monotonic=server.time.monotonic()+5)
        server._kill_reply_sample(record, 'unapproved-stage')
        self.assertEqual(record['samples'], [])
        for _ in range(10):
            server._kill_reply_sample(record, 'db-entry')
        self.assertEqual(len(record['samples']), 9)
        server._kill_reply_sample({}, 'db-entry')
        server._kill_reply_sample(None, 'db-entry')
        with patch.object(server.time, 'monotonic', side_effect=RuntimeError('clock unavailable')):
            server._kill_reply_sample({'proof': record['proof'], 'samples': []}, 'db-entry')
