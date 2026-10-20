"""Signed work reads at actual Hub stream and terminal notification boundaries."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from datetime import timedelta
import hashlib
import json
import os
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.server import _WorkBellTransport
from hub.client_launch_session import ApplicationSessionFailure
from hub.tests.test_hub_offline import reg
from identity.test_authority import NOW
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient
from .legacy_work_client import LegacyWorkCommandClient
from .local_work_client import LocalWorkClient
from . import test_local_work_hub as local_support
from .test_work_bridge_owner import WorkBridgeFixture


class WorkBackgroundTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    open_client = local_support.LocalWorkHubReadTests.open_client
    session_for = local_support.LocalWorkHubReadTests.session_for
    agent = local_support.LocalWorkHubReadTests.agent
    target = local_support.LocalWorkHubReadTests.target
    install_client = local_support.LocalWorkHubReadTests.install_client

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.local_work_client',
                'capability_owner.federated_work_client', 'hub.server'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.caller = 'operator'
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        import weakref
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('background-work-proof', default=None)
        original_db = self.hub.db
        async def checked_db(function, *args, **kwargs):
            if function in (self.store.work, self.store.claimable):
                raise AssertionError('Hub caller bypassed the signed work owner')
            if function in (self.store.q, self.store.q1) and args and 'work_items' in args[0].lower():
                raise AssertionError('Hub caller queried work SQL directly')
            return await original_db(function, *args, **kwargs)
        self.hub.db = checked_db
        await self.open_client()
        self.install_client()
        from hub.fed.runtime import Federation
        self.hub.fed = object.__new__(Federation)
        self.hub.fed.hub, self.hub.fed._qualified_work = self.hub, True
        self.hub.fed.verbs, self.hub.fed.plugin_verbs = self.hub.fed._core_verbs(), {}
        self.hub.subscribers = 0
        self.hub.bell, self.hub.rings, self.hub.inflight = {}, {}, set()
        self.hub.cfg['bell_every_s'] = 30

    async def subscribe(self, *, token='operator-secret', attribution=None, stream='mail', drain=None, tcp=True):
        arguments = {'stream': stream}
        request = {'verb': 'subscribe', 'args': arguments}
        if tcp:
            request['token'] = token
        if attribution is not None:
            request['as'] = attribution
        frames = []
        self.stream_done = False
        async def flushed():
            if drain is not None:
                await drain(frames)
        writer = SimpleNamespace(write=Mock(side_effect=lambda raw: frames.append(json.loads(raw))),
            drain=flushed, close=Mock(), is_closing=lambda: self.stream_done,
            get_extra_info=lambda _: object())
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()),
            at_eof=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=tcp)
        return frames, writer

    async def agent_token(self):
        await self.agent(maximum=2)
        self.install_client()
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        return 'agent-secret'

    async def test_actual_subscription_uses_signed_scoped_read_and_preserves_mail(self):
        token = await self.agent_token()
        visible = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Visible subscribed work')
        hidden = self.store.work_create('operator', 'other', 'role:*/worker', 'Hidden subscribed work')
        message = self.store.post('virtual:operator', 'agent:' + self.caller, 'note', 'Original mail')
        before = self.store.q1('SELECT state FROM deliveries WHERE message_id=?', (message['id'],))['state']
        async def drain(frames):
            if 'claimable' in frames[-1]:
                self.stream_done = True
        frames, writer = await self.subscribe(token=token, drain=drain)
        self.assertEqual(frames[0], {'ok': True, 'caller': self.caller, 'subscribed': 'mail'})
        self.assertEqual([row['id'] for row in frames[-1]['claimable']], [visible['id']])
        self.assertEqual(frames[1]['message']['id'], message['id'])
        self.assertNotIn(hidden['id'], canonical_bytes(frames).decode())
        self.assertEqual(self.store.q1('SELECT state FROM deliveries WHERE message_id=?', (message['id'],))['state'], before)
        self.assertEqual(self.hub.subscribers, 0)
        self.assertEqual(len(self.commands._disclosures), 0)
        writer.close.assert_called_once()

    async def test_completed_poll_does_not_keep_old_private_deadline(self):
        token = await self.agent_token()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'First poll')
        record = strict_loads(self.js.messages[-1].data)
        grant = next(g for g in record['state']['grants'] if g['ref'] == self.work_grants['human']['federation-work-read'])
        grant['expiresAt'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(record)
        original_sleep, polls = asyncio.sleep, 0
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        async def interval(delay):
            nonlocal polls
            if delay == 0.5:
                polls += 1
                self.assertEqual(len(self.commands._disclosures), 0)
                if polls == 1:
                    grant['expiresAt'] = (NOW + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
                    self.js.messages[-1].data = canonical_bytes(record)
                    self.store.work_create('operator', 'falcon', 'role:*/worker', 'Second poll')
                    timer = patch('capability_owner.legacy_work_client.datetime', Later)
                    timer.start()
                    self.addCleanup(timer.stop)
                await original_sleep(0)
            else:
                await original_sleep(delay)
        async def drain(frames):
            if sum('claimable' in frame for frame in frames) == 2:
                self.stream_done = True
        with patch('hub.server.asyncio.sleep', side_effect=interval):
            frames, _ = await self.subscribe(token=token, drain=drain)
        claims = [frame['claimable'] for frame in frames if 'claimable' in frame]
        self.assertEqual([len(rows) for rows in claims], [1, 2])
        self.assertTrue(all('ok' not in frame or frame['ok'] for frame in frames))

    async def test_revoked_actual_token_stops_before_next_frame(self):
        token = await self.agent_token()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Must stay private')
        async def drain(frames):
            if 'subscribed' in frames[-1]:
                self.store.db.execute('UPDATE agents SET token_sha=NULL WHERE session=?', (self.caller,))
        frames, _ = await self.subscribe(token=token, drain=drain)
        self.assertEqual(len(frames), 2)
        self.assertIn('subscribed', frames[0])
        self.assertFalse(frames[1]['ok'])
        self.assertFalse(any('claimable' in frame for frame in frames))
        self.assertEqual(len(self.commands._disclosures), 0)

    async def test_target_changes_after_signed_read_before_stream_write(self):
        token = await self.agent_token()
        row = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Never sent')
        original = self.client.readiness
        async def changed(*args, **kwargs):
            result = await original(*args, **kwargs)
            self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (self.caller,))
            return result
        with patch.object(self.client, 'readiness', side_effect=changed):
            frames, _ = await self.subscribe(token=token)
        self.assertNotIn(row['id'], canonical_bytes(frames).decode())
        self.assertFalse(frames[-1]['ok'])

    async def test_cancel_during_frame_drain_joins_original_poll_and_clears_metadata(self):
        token = await self.agent_token()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Unfinished frame')
        entered, joined = asyncio.Event(), asyncio.Event()
        async def drain(frames):
            if 'claimable' in frames[-1]:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    joined.set()
        original = asyncio.create_task(self.subscribe(token=token, drain=drain))
        await asyncio.wait_for(entered.wait(), 5)
        original.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await original
        self.assertTrue(joined.is_set())
        self.assertEqual(self.hub.subscribers, 0)
        self.assertEqual(len(self.commands._disclosures), 0)
        self.assertEqual(len(self.commands._workers), 0)
        self.assertEqual(len(self.hub._authenticated_callers), 0)

    async def test_events_still_require_operator(self):
        token = await self.agent_token()
        frames, _ = await self.subscribe(token=token, stream='events')
        self.assertFalse(frames[-1]['ok'])
        self.assertEqual(self.hub.subscribers, 0)

    async def open_service(self):
        await self.commands.close(timeout=None)
        self.caller = 'federation'
        self.session = self.session_for('service', 'falcon', self.endpoint)
        self.commands = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = LocalWorkClient(self.hub, self.commands)
        self.install_client()
        self.hub.fed.session = None
        self.service_client = FederatedWorkCommandClient(self.hub.fed, self.commands)
        self.hub.fed._work_commands = self.service_client

    def terminal_agent(self, *, repo='falcon', maximum=2):
        session = self.target(repo=repo, maximum=maximum)
        self.store.db.execute('UPDATE agents SET handle=?, pane_pid=? WHERE session=?', ('%42', 4200, session))
        return session

    async def test_bell_uses_service_scope_and_global_capacity(self):
        target = self.terminal_agent(maximum=1)
        hidden = self.store.work_create('operator', 'other', 'agent:' + target, 'Hidden active work')
        self.store.claim(target, work_id=hidden['id'])
        ready = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Visible ready work')
        await self.open_service()
        with patch.object(self.hub, '_start_ring') as ring:
            await self.hub._bell_pass()
        ring.assert_not_called()
        self.assertTrue(self.submitted)
        self.assertTrue(all(c['payload']['input'].get('query', {}).get('session') == target
            for c in self.submitted if c['contractId'] == 'federation-work-read'))
        self.assertEqual(self.submitted[-1]['transportRef']['id'], 'legacy-service-transport')
        self.assertEqual(len(self.commands._disclosures), 0)
        self.assertEqual(len(self.service_client._sessions), 0)

    async def test_bell_unselected_repository_keeps_mail_only_without_work_read(self):
        target = self.terminal_agent(repo='other')
        self.store.post('virtual:operator', 'agent:' + target, 'note', 'Mail only')
        self.store.work_create('operator', 'other', 'role:*/worker', 'Unselected work')
        await self.open_service()
        with patch.object(self.hub, '_start_ring') as ring:
            await self.hub._bell_pass()
        ring.assert_called_once()
        self.assertEqual(ring.call_args.args[1:3], (1, 0))
        self.assertIsNone(ring.call_args.kwargs['work_read'])
        self.assertEqual(self.submitted, [])

    async def test_bell_snapshot_refuses_generation_or_source_change_at_transport_use(self):
        target = self.terminal_agent()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Original bell')
        await self.open_service()
        with patch.object(self.hub, '_start_ring') as ring:
            await self.hub._bell_pass()
        guard = ring.call_args.kwargs['work_read']
        transport = SimpleNamespace(handle=Mock(return_value=('%42', 4200)), send_text=Mock())
        checked = _WorkBellTransport(transport, target, '%42', 4200, Event(), guard)
        await asyncio.to_thread(checked.send_text, '%42', 'Original count')
        transport.send_text.assert_called_once()
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target,))
        with self.assertRaises(Exception):
            await asyncio.to_thread(checked.send_text, '%42', 'Changed generation')
        transport.send_text.assert_called_once()
        self.store.db.execute('UPDATE agents SET generation=generation-1 WHERE session=?', (target,))
        self.session._stopped = True
        with self.assertRaises(Exception):
            await asyncio.to_thread(checked.send_text, '%42', 'Stopped source')
        transport.send_text.assert_called_once()

    async def test_human_only_selection_preserves_mail_bells_without_borrowing_credentials(self):
        target = self.terminal_agent()
        self.store.post('virtual:operator', 'agent:' + target, 'note', 'Mail only')
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Not a service grant')
        self.hub.fed.session = None
        self.service_client = FederatedWorkCommandClient(self.hub.fed, self.commands)
        self.hub.fed._work_commands = self.service_client
        with patch.object(self.hub, '_start_ring') as ring:
            await self.hub._bell_pass()
        ring.assert_called_once()
        self.assertEqual(ring.call_args.args[1:3], (1, 0))
        self.assertEqual(self.submitted, [])

    async def test_selected_stopped_service_cannot_be_treated_as_absent(self):
        self.terminal_agent()
        await self.open_service()
        self.session._stopped = True
        with patch.object(self.hub, '_start_ring') as ring:
            with self.assertRaises(ApplicationSessionFailure):
                await self.hub._bell_pass()
        ring.assert_not_called()

    async def test_actual_ring_retains_expiry_before_delayed_terminal_input(self):
        target = self.terminal_agent()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Original bell count')
        await self.open_service()
        self.hub.io = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.io.shutdown, wait=True)
        self.hub.started, self.hub.awaiting = {}, {}
        self.hub.tp = SimpleNamespace(handle=Mock(return_value=('%42', 4200)), send_text=Mock())
        entered, released = Event(), Event()
        self.addCleanup(released.set)
        original_now = _Clock.now()
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return original_now + timedelta(seconds=10)
        def deliver(transport, profile, session, handle, text, **kwargs):
            entered.set()
            if not released.wait(5):
                raise AssertionError('test did not release its original worker')
            transport.send_text(handle, text)
            from hub.deliver import Receipt
            return Receipt(outcome='submitted')
        profile = SimpleNamespace(bell=lambda **kwargs: 'Private work count')
        with patch('hub.server.profiles.get', return_value=profile), patch('hub.server.deliver.deliver_line', side_effect=deliver):
            await self.hub._bell_pass()
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            with patch('capability_owner.legacy_work_client.datetime', Later):
                released.set()
                await asyncio.gather(*(task for task, _ in tuple(self.hub.rings.values())))
        self.hub.tp.send_text.assert_not_called()
        self.assertEqual(self.hub.inflight, set())
        self.assertEqual(self.hub.rings, {})

    async def test_bell_snapshot_does_not_follow_a_replaced_service_session(self):
        target = self.terminal_agent()
        self.store.work_create('operator', 'falcon', 'role:*/worker', 'Original service session')
        await self.open_service()
        with patch.object(self.hub, '_start_ring') as ring:
            await self.hub._bell_pass()
        guard = ring.call_args.kwargs['work_read']
        transport = SimpleNamespace(handle=Mock(return_value=('%42', 4200)), send_text=Mock())
        checked = _WorkBellTransport(transport, target, '%42', 4200, Event(), guard)
        self.hub.fed.session = SimpleNamespace(check_open=Mock())
        with self.assertRaises(Exception):
            await asyncio.to_thread(checked.send_text, '%42', 'Must not be typed')
        transport.send_text.assert_not_called()


    async def test_unix_operator_attribution_keeps_actual_operator_read_authority(self):
        target = self.target()
        visible = self.store.work_create('operator', 'falcon', 'role:*/worker', 'Scoped Unix work')
        hidden = self.store.work_create('operator', 'other', 'role:*/worker', 'Hidden Unix work')
        async def drain(frames):
            if 'claimable' in frames[-1]:
                self.stream_done = True
        with patch.object(self.hub, 'peer', return_value=(98765, os.getuid())), patch.object(
                self.hub, 'identify_qualified', return_value=(None, False)):
            frames, _ = await self.subscribe(tcp=False, attribution=target, drain=drain)
        self.assertEqual(frames[0], {'ok': True, 'caller': target, 'subscribed': 'mail'})
        self.assertEqual([row['id'] for row in frames[-1]['claimable']], [visible['id']])
        self.assertNotIn(hidden['id'], canonical_bytes(frames).decode())
        reads = [claim for claim in self.submitted if claim['contractId'] == 'federation-work-read']
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]['payload']['input']['query']['session'], target)
        self.assertEqual(reads[0]['transportRef']['id'], 'transport')
        self.assertEqual(reads[0]['grantRef'], self.work_grants['human']['federation-work-read'])
        self.assertEqual(len(self.commands._disclosures), 0)

    async def test_actual_idle_socket_disconnect_releases_the_subscription(self):
        token = await self.agent_token()
        handlers = set()
        async def connected(reader, writer):
            original = asyncio.current_task()
            handlers.add(original)
            try:
                await self.hub.handle_conn(reader, writer, tcp=True)
            finally:
                writer.close()
                await writer.wait_closed()
                handlers.discard(original)
        server = await asyncio.start_server(connected, '127.0.0.1', 0)
        writer = None
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            writer.write(canonical_bytes({'verb': 'subscribe', 'args': {'stream': 'mail'}, 'token': token}) + b'\n')
            await writer.drain()
            acknowledgement = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertEqual(acknowledgement['subscribed'], 'mail')
            claimable = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertIn('claimable', claimable)
            writer.close()
            await writer.wait_closed()
            deadline = asyncio.get_running_loop().time() + 2
            while self.hub.subscribers and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.05)
            self.assertEqual(self.hub.subscribers, 0)
            self.assertEqual(len(self.commands._disclosures), 0)
            self.assertEqual(len(self.hub._authenticated_callers), 0)
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            server.close()
            originals = tuple(handlers)
            for original in originals:
                original.cancel()
            await asyncio.gather(*originals, return_exceptions=True)
            await server.wait_closed()
