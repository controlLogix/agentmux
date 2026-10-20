"""Authorize the complete shutdown reply before releasing Hub teardown."""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from capability_owner.test_work_rpc import WorkRpcTests
from hub.core_endpoint import SelectedCoreRequest, selected_core_request
from hub.store import HubError


class ShutdownReplyTests(WorkRpcTests):
    def shutdown_connection(self, *, write=None, drain=None, token='operator-secret'):
        self.hub._selected_endpoint = SimpleNamespace(check=Mock(),
            route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}}))
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps({
            'verb': 'shutdown', 'args': {}, 'token': token}).encode()))
        replies = []
        def send(raw):
            if write is not None:
                write(raw)
            replies.append(json.loads(raw))
        writer = SimpleNamespace(write=send, drain=drain or AsyncMock(),
            close=Mock(), is_closing=lambda: False)
        async def invoke():
            context = selected_core_request.set(SelectedCoreRequest(
                self.hub._selected_endpoint, 'falcon', '/falcon', asyncio.current_task()))
            try:
                await self.hub.handle_conn(reader, writer, tcp=True)
            finally:
                selected_core_request.reset(context)
        return invoke, writer, replies

    async def test_delayed_final_validation_does_not_start_own_teardown(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.hub._check_work_targets
        async def delayed():
            entered.set()
            await release.wait()
            await original()
        invoke, writer, replies = self.shutdown_connection()
        task = watcher = None
        async def cleanup_connection():
            await self.hub.stop.wait()
            if not task.done():
                task.cancel()
        with patch.object(self.hub, '_check_work_targets', side_effect=delayed):
            try:
                task = asyncio.create_task(invoke())
                watcher = asyncio.create_task(cleanup_connection())
                await asyncio.wait_for(entered.wait(), 2)
                await asyncio.sleep(0)
                self.assertFalse(self.hub.stop.is_set())
                self.assertFalse(task.done())
                self.assertEqual(replies, [])
                release.set()
                await asyncio.wait_for(asyncio.shield(task), 2)
                await asyncio.wait_for(watcher, 2)
            finally:
                for owned in (task, watcher):
                    if owned is not None and not owned.done():
                        owned.cancel()
                await asyncio.gather(*(owned for owned in (task, watcher)
                    if owned is not None), return_exceptions=True)
        self.assertTrue(self.hub.stop.is_set())
        self.assertEqual(replies, [{'ok': True, 'caller': 'operator',
            'result': {'stopping': True}}])
        writer.close.assert_called_once()

    async def test_refusal_or_expiry_before_acceptance_does_not_stop(self):
        invoke, writer, replies = self.shutdown_connection()
        with patch.object(self.hub, '_check_work_targets', side_effect=HubError('permission revoked')):
            await invoke()
        self.assertFalse(self.hub.stop.is_set())
        self.assertEqual(replies, [{'ok': False, 'error': 'permission revoked'}])
        writer.close.assert_called_once()

    async def test_original_deadline_expiring_during_validation_does_not_stop(self):
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        original = self.hub._check_work_targets
        expiry = []
        async def validate():
            admitted = self.hub._work_reply_identity[asyncio.current_task()][0]
            expiry.append(admitted.expires_monotonic)
            clock[0] = admitted.expires_monotonic + .001
            await original()
        invoke, writer, replies = self.shutdown_connection()
        with patch('hub.server.time', timer), \
                patch.object(self.hub, '_check_work_targets', side_effect=validate):
            await invoke()
        self.assertEqual(len(expiry), 1)
        self.assertFalse(self.hub.stop.is_set())
        self.assertFalse(replies[0]['ok'])
        self.assertIn('authenticated work request changed or expired', replies[0]['error'])
        writer.close.assert_called_once()

    async def test_invalid_token_does_not_stop(self):
        invoke, writer, replies = self.shutdown_connection(token='not-authorized')
        await invoke()
        self.assertFalse(self.hub.stop.is_set())
        self.assertFalse(replies[0]['ok'])
        writer.close.assert_called_once()

    async def test_endpoint_refusal_before_acceptance_does_not_stop(self):
        invoke, writer, replies = self.shutdown_connection()
        # Authentication and dispatch checks succeed; invalidate after final Work checks.
        original = self.hub._check_work_targets
        async def validate():
            await original()
            self.hub._selected_endpoint.check.side_effect = HubError('endpoint changed')
        with patch.object(self.hub, '_check_work_targets', side_effect=validate):
            with self.assertRaisesRegex(HubError, 'endpoint changed'):
                await invoke()
        self.assertFalse(self.hub.stop.is_set())
        self.assertEqual(replies, [])
        self.assertEqual(self.hub._selected_endpoint.check.call_count, 3)
        writer.close.assert_called_once()

    async def test_cancellation_before_acceptance_does_not_stop(self):
        entered = asyncio.Event()
        async def validate():
            entered.set()
            await asyncio.Event().wait()
        invoke, writer, replies = self.shutdown_connection()
        with patch.object(self.hub, '_check_work_targets', side_effect=validate):
            task = asyncio.create_task(invoke())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        self.assertFalse(self.hub.stop.is_set())
        self.assertEqual(replies, [])
        writer.close.assert_called_once()

    async def test_accepted_drain_times_out_and_joins_after_five_seconds(self):
        entered, finished = asyncio.Event(), asyncio.Event()
        async def drain():
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                finished.set()
        invoke, writer, replies = self.shutdown_connection(drain=drain)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(invoke(), 8)
        self.assertTrue(entered.is_set())
        self.assertTrue(finished.is_set())
        self.assertGreaterEqual(time.monotonic() - started, 5)
        self.assertLess(time.monotonic() - started, 7)
        self.assertTrue(self.hub.stop.is_set())
        self.assertEqual(len(replies), 1)
        writer.close.assert_called_once()

    async def test_accepted_write_or_drain_failure_still_stops(self):
        for stage in ('write', 'drain'):
            with self.subTest(stage=stage):
                self.hub.stop.clear()
                failure = ConnectionError('delivery failed')
                invoke, writer, replies = self.shutdown_connection(
                    write=Mock(side_effect=failure) if stage == 'write' else None,
                    drain=AsyncMock(side_effect=failure) if stage == 'drain' else None)
                with self.assertRaises(ConnectionError):
                    await invoke()
                self.assertTrue(self.hub.stop.is_set())
                self.assertEqual(len(replies), 0 if stage == 'write' else 1)
                writer.close.assert_called_once()

    async def test_accepted_drain_cancellation_still_stops_and_joins(self):
        entered = asyncio.Event()
        async def drain():
            entered.set()
            await asyncio.Event().wait()
        invoke, writer, replies = self.shutdown_connection(drain=drain)
        task = asyncio.create_task(invoke())
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(self.hub.stop.is_set())
        self.assertEqual(len(replies), 1)
        writer.close.assert_called_once()

    async def test_postwrite_disclosure_failure_still_stops(self):
        original = self.hub._check_work_response
        def check(value=None, *, finish=False):
            if finish:
                raise HubError('original disclosure expired')
            return original(value, finish=finish)
        invoke, writer, replies = self.shutdown_connection()
        with patch.object(self.hub, '_check_work_response', side_effect=check):
            with self.assertRaisesRegex(HubError, 'original disclosure expired'):
                await invoke()
        self.assertTrue(self.hub.stop.is_set())
        self.assertEqual(len(replies), 1)
        writer.close.assert_called_once()

    async def test_external_stop_remains_set_when_request_refuses(self):
        self.hub.stop.set()
        invoke, writer, replies = self.shutdown_connection(token='not-authorized')
        await invoke()
        self.assertTrue(self.hub.stop.is_set())
        self.assertFalse(replies[0]['ok'])
        writer.close.assert_called_once()
