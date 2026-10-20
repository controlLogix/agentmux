"""A completed kill is queried in its original parent without another effect."""
import asyncio
import json
import unittest
from unittest.mock import patch

from .test_kill_admission_turn import KillAdmissionTurnTests
from .test_work_source import SelectedWorkSourceFixture


class CompletedKillQueryTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = KillAdmissionTurnTests.configure_channels
    asyncSetUp = KillAdmissionTurnTests.asyncSetUp
    join_tasks = KillAdmissionTurnTests.join_tasks
    task = KillAdmissionTurnTests.task
    gate = KillAdmissionTurnTests.gate
    framed_connection = KillAdmissionTurnTests.framed_connection
    registered = KillAdmissionTurnTests.registered
    prepare = KillAdmissionTurnTests.prepare

    async def completed(self):
        request = await self.prepare()
        with patch.object(self.hub, 'harness', return_value=True) as physical:
            first = await self.framed_connection(request)
            self.assertTrue(first['ok'], first)
            physical.assert_called_once()
        return request, await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k')

    async def test_parent_query_preserves_records_and_blocks_readers_through_final_check(self):
        request, saved = await self.completed()
        auth, check = self.hub.authenticate_caller, self.hub._check_work_request_current
        finished, queued = self.gate(), self.gate()
        tasks, calls, owners = [], [], []
        call = self.maintenance._commands._call
        async def read():
            queued.set()
            async with self.maintenance.observation_read_turn():
                finished.set()
        async def authenticated(*args, **kwargs):
            result = await auth(*args, **kwargs)
            owners.append(asyncio.current_task())
            tasks.append(self.task(read()))
            await queued.wait()
            return result
        async def called(session, contract, *args, **kwargs):
            calls.append(contract)
            self.assertFalse(finished.is_set())
            return await call(session, contract, *args, **kwargs)
        def checked(*args):
            self.assertFalse(finished.is_set())
            self.assertIs(self.maintenance._kill_admission_turn['owner'], owners[0])
            return check(*args)
        with patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch.object(self.hub, '_check_work_request_current', side_effect=checked), \
                patch.object(self.maintenance._commands, '_call', side_effect=called), \
                patch.object(self.hub, 'identify_qualified', wraps=self.hub.identify_qualified) as identify, \
                patch.object(self.hub, '_kill_agent', side_effect=AssertionError('physical path entered')), \
                patch.object(self.hub, '_apply_kill', side_effect=AssertionError('callback entered')), \
                patch.object(self.hub, '_record_kill', side_effect=AssertionError('metadata write entered')), \
                patch.object(self.maintenance._client, '_write', side_effect=AssertionError('lifecycle write entered')):
            result = await self.framed_connection(request)
            await asyncio.gather(*tasks)
            self.assertTrue(result['ok'], result)
            self.assertEqual(identify.call_count, 2)
        self.assertEqual(calls, ['federation-work-inspect', 'federation-work-inspect', 'federation-work-outcome'])
        self.assertTrue(finished.is_set())
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k'), saved)
        self.assertIsNone(self.maintenance._kill_admission_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_conflicting_metadata_refuses_without_physical_fallback(self):
        request, _ = await self.completed()
        rows = await self.hub.db(self.hub.store.q, "SELECT k,v FROM fed_state WHERE k LIKE '%:metadata'")
        self.assertEqual(len(rows), 1)
        await self.hub.db(self.hub.store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
            (json.dumps({'operationId': 'different-original'}), rows[0]['k']))
        with patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            fallback.assert_not_awaited()
        self.assertIsNone(self.maintenance._kill_admission_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_cancelled_outcome_joins_original_query_before_unlocking(self):
        request, saved = await self.completed()
        entered, release = self.gate(), self.gate()
        call = self.maintenance._commands._call
        completed = []
        async def called(session, contract, *args, **kwargs):
            if contract == 'federation-work-outcome':
                entered.set()
                await release.wait()
                result = await call(session, contract, *args, **kwargs)
                completed.append(True)
                return result
            return await call(session, contract, *args, **kwargs)
        with patch.object(self.maintenance._commands, '_call', side_effect=called), \
                patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
            connection = self.task(self.framed_connection(request))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                reservation = self.maintenance._kill_admission_turn
                owner = reservation['owner']
                for _ in range(2):
                    owner.cancel()
                    await asyncio.sleep(.02)
                    self.assertFalse(owner.done())
                    self.assertIs(self.maintenance._kill_admission_turn, reservation)
                    self.assertFalse(completed)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await connection
            finally:
                release.set()
                await asyncio.gather(connection, return_exceptions=True)
        self.assertTrue(completed)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k'), saved)
        self.assertIsNone(self.maintenance._kill_admission_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_missing_metadata_releases_to_original_recovery_without_repeating_effect(self):
        request, _ = await self.completed()
        await self.hub.db(self.hub.store.db.execute, "DELETE FROM fed_state WHERE k LIKE '%:metadata'")
        kill = self.hub._kill_agent
        async def original(*args):
            self.assertIsNone(self.maintenance._kill_admission_turn)
            return await kill(*args)
        with patch.object(self.hub, '_kill_agent', side_effect=original) as fallback, \
                patch.object(self.hub, 'harness', side_effect=AssertionError('repeated physical effect')):
            result = await self.framed_connection(request)
            self.assertTrue(result['ok'], result)
            fallback.assert_awaited_once()

    async def test_revoked_current_outcome_refuses_without_fallback(self):
        from .test_hub_lifecycle_disclosure import HubLifecycleDisclosureTests
        request, saved = await self.completed()
        HubLifecycleDisclosureTests.revoke(self, 'outcome')
        with patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            fallback.assert_not_awaited()
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k'), saved)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_new_termination_during_query_refuses_without_fallback(self):
        request, saved = await self.completed()
        confirm = self.maintenance._client.confirm_disclosure
        session = request['args']['session']
        async def changed(*args, **kwargs):
            result = await confirm(*args, **kwargs)
            self.hub.terminating.add(session)
            return result
        try:
            with patch.object(self.maintenance._client, 'confirm_disclosure', side_effect=changed), \
                    patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
                result = await self.framed_connection(request)
                self.assertFalse(result['ok'], result)
                fallback.assert_not_awaited()
        finally:
            self.hub.terminating.discard(session)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k'), saved)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_changed_completed_record_cannot_submit_after_locked_reload(self):
        from agentmux_contracts import canonical_bytes, strict_loads
        request, _ = await self.completed()
        client = self.maintenance._client
        execute = client.execute
        async def replaced(command, arguments, *, operation_id, expires, **kwargs):
            row = await self.hub.db(self.hub.store.q1, 'SELECT v FROM fed_state WHERE k=?', (client._key(operation_id),))
            record = strict_loads(row['v'])
            record.update(state='prepared', result=None, receipts=[])
            await self.hub.db(self.hub.store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
                (canonical_bytes(record).decode(), client._key(operation_id)))
            return await execute(command, arguments, operation_id=operation_id, expires=expires, **kwargs)
        with patch.object(client, 'execute', side_effect=replaced), \
                patch.object(client, '_exchange', side_effect=AssertionError('exchange after replacement')) as exchange, \
                patch.object(client, '_write', side_effect=AssertionError('write after replacement')) as write, \
                patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            fallback.assert_not_awaited()
            exchange.assert_not_awaited()
            write.assert_not_called()
        self.assertFalse(self.maintenance._lock.locked())

    async def test_target_changed_before_final_check_refuses_without_diagnostics(self):
        request, _ = await self.completed()
        check = self.hub._check_work_targets
        async def changed(*args, **kwargs):
            self.hub._kill_reply_timings.clear()
            await self.hub.db(self.hub.store.db.execute,
                'UPDATE agents SET generation=generation+1 WHERE session=?', (request['args']['session'],))
            return await check(*args, **kwargs)
        with patch.object(self.hub, '_check_work_targets', side_effect=changed), \
                patch.object(self.hub, '_kill_agent', side_effect=AssertionError('fallback entered')) as fallback:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            fallback.assert_not_awaited()
        self.assertFalse(self.maintenance._lock.locked())

    async def test_query_preserves_prior_disclosure_minimum(self):
        from datetime import datetime, timedelta, timezone
        request, _ = await self.completed()
        confirm = self.maintenance.confirm_completed_kill
        disclose = self.maintenance._client.confirm_disclosure
        bounds = []
        async def bounded(agent):
            bound = datetime.now(timezone.utc) + timedelta(seconds=2)
            bounds.append(bound)
            self.maintenance._commands._remember((), bound)
            return await confirm(agent)
        async def disclosure(*args, **kwargs):
            self.assertLessEqual(kwargs['expires'], bounds[0])
            self.assertFalse(kwargs['finish'])
            return await disclose(*args, **kwargs)
        with patch.object(self.maintenance, 'confirm_completed_kill', side_effect=bounded), \
                patch.object(self.maintenance._client, 'confirm_disclosure', side_effect=disclosure) as called:
            result = await self.framed_connection(request)
            self.assertTrue(result['ok'], result)
            called.assert_awaited_once()

    async def test_final_snapshot_read_cannot_outlive_original_proof(self):
        import time
        from unittest.mock import Mock
        request, saved = await self.completed()
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        read = self.maintenance._completed_kill
        calls = []
        def expires(*args):
            result = read(*args)
            calls.append(True)
            if len(calls) == 4:
                clock[0] += 6
            return result
        with patch.object(self.maintenance, '_completed_kill', side_effect=expires), \
                patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer):
            result = await self.framed_connection(request, expires=clock[0]+10)
            self.assertFalse(result['ok'], result)
            self.assertIn('authenticated work request changed or expired', result['error'])
        self.assertEqual(len(calls), 4)
        self.assertEqual(await self.hub.db(self.hub.store.q, 'SELECT k,v FROM fed_state ORDER BY k'), saved)
        self.assertFalse(self.maintenance._lock.locked())
