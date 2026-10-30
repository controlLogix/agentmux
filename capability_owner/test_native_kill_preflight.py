"""Selected native kill retains its required post-authentication source check."""
import json
import time
import unittest
from unittest.mock import Mock, patch
from identity.work_client import WORK_COMMAND_SECONDS
from .test_adopt_request_turn import AdoptRequestTurnTests
from .test_hub_work_maintenance import HubWorkMaintenanceTests
from .test_work_source import SelectedWorkSourceFixture


class NativeKillPreflightTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = AdoptRequestTurnTests.configure_channels
    asyncSetUp = AdoptRequestTurnTests.asyncSetUp
    join_tasks = AdoptRequestTurnTests.join_tasks
    task = AdoptRequestTurnTests.task
    gate = AdoptRequestTurnTests.gate
    framed_connection = AdoptRequestTurnTests.framed_connection
    registered = HubWorkMaintenanceTests.registered

    async def test_post_auth_source_wait_still_expires_original_proof(self):
        agent = await self.registered()
        request = {'verb': 'kill', 'args': {'session': agent['session']},
                   'operationId': 'native-kill-original'}
        self.hub._native_core = object()
        events, proofs = [], []
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        verify, authenticate = self.binding.verify, self.hub.authenticate_caller
        async def verified():
            events.append('source')
            if proofs:
                # Controlled queue cost crosses the unchanged original proof while
                # the selected envelope stays live, so the proof is what refuses.
                clock[0] += WORK_COMMAND_SECONDS + 1
            return await verify()
        async def authenticated(*args, **kwargs):
            proof = await authenticate(*args, **kwargs)
            proofs.append(self.hub._authenticated_callers[proof])
            events.append('authenticated')
            return proof
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer), \
                patch.object(self.hub, 'harness', return_value=True) as physical, \
                patch('hub.server.log') as log:
            try:
                result = await self.framed_connection(request, expires=clock[0] + 15)
            finally:
                records = await self.hub.db(self.hub.store.q,
                    "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.operationId')=?",
                    (request['operationId'],))
                print(json.dumps({'events': events, 'physicalCalls': physical.call_count,
                    'retainedPhases': [json.loads(r['v'])['identity']['phase'] for r in records],
                    'proofRemaining': None if not proofs else proofs[0].expires_monotonic-clock[0],
                    'refusals': [c.args for c in log.call_args_list]}))
            self.assertFalse(result['ok'], result)
            self.assertIn('authenticated caller proof unavailable', result['error'])
            self.assertEqual(events, ['authenticated', 'source'])
            self.assertIsNone(proofs[0].work_source_preflight)
            self.assertEqual(proofs[0].expires_monotonic - clock[0], -1)
            physical.assert_not_called()
            self.assertFalse(records)

    async def test_framed_kill_preserves_managed_and_attributed_refusals(self):
        agent = await self.registered()
        self.hub._native_core = object()
        for classification, attribution in ((('falcon-worker-one', True), None),
                ((None, False), 'falcon-worker-one'), (('falcon-worker-one', True), 'operator')):
            request = {'verb': 'kill', 'args': {'session': agent['session']},
                       'operationId': 'refused-native-kill'}
            if attribution is not None:
                request['as'] = attribution
            with self.subTest(classification=classification, attribution=attribution), \
                    patch.object(self.hub, 'identify_qualified', return_value=classification), \
                    patch.object(self.hub, 'harness', return_value=True) as physical:
                result = await self.framed_connection(request)
                self.assertFalse(result['ok'], result)
                physical.assert_not_called()

    async def test_framed_kill_rechecks_source_after_identity(self):
        agent = await self.registered()
        self.hub._native_core = object()
        identity = self.hub._caller_identity
        async def changed(*args, **kwargs):
            result = await identity(*args, **kwargs)
            self.hub.cfg['nats_url'] = 'nats://changed.invalid'
            return result
        old = self.hub.cfg.get('nats_url')
        try:
            with patch.object(self.hub, '_caller_identity', side_effect=changed), \
                    patch.object(self.hub, 'harness', return_value=True) as physical:
                result = await self.framed_connection({'verb':'kill',
                    'args':{'session':agent['session']},'operationId':'changed-source-kill'})
                self.assertFalse(result['ok'], result)
                physical.assert_not_called()
                self.assertFalse(self.hub._authenticated_callers)
        finally:
            if old is None:
                self.hub.cfg.pop('nats_url', None)
            else:
                self.hub.cfg['nats_url'] = old

    async def test_framed_wrong_uid_refuses_before_source_read(self):
        from hub import server
        agent = await self.registered()
        self.hub._native_core = object()
        with patch.object(self.hub, 'peer', return_value=(123, server.os.getuid()+1)), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify, \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            result = await self.framed_connection({'verb':'kill',
                'args':{'session':agent['session']},'operationId':'wrong-uid-kill'})
            self.assertFalse(result['ok'], result)
            verify.assert_not_awaited()
            physical.assert_not_called()

    async def test_framed_original_envelope_orders_identity_source_effect_and_replay(self):
        agent = await self.registered()
        self.hub._native_core = object()
        request = {'verb':'kill', 'args':{'session':agent['session'], 'reason':'original'},
                   'operationId':'framed-native-original'}
        events, proofs = [], []
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        verify, identity, authenticate = self.binding.verify, self.hub._caller_identity, self.hub.authenticate_caller
        async def verified():
            events.append('source')
            clock[0] += 3
            return await verify()
        async def identified(*args, **kwargs):
            events.append('identity')
            return await identity(*args, **kwargs)
        async def authenticated(*args, **kwargs):
            result = await authenticate(*args, **kwargs)
            proofs.append(self.hub._authenticated_callers[result])
            return result
        def terminated(*args, **kwargs):
            events.append('physical')
            return True
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, '_caller_identity', side_effect=identified), \
                patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch.object(self.hub, 'harness', side_effect=terminated) as physical, \
                patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer):
            start = clock[0]
            expires = start+WORK_COMMAND_SECONDS+2
            result = await self.framed_connection(request, expires=expires)
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['result'], {'killed':agent['session']})
            self.assertEqual(events, ['identity', 'source', 'physical'])
            self.assertEqual(proofs[0].expires_monotonic, min(expires, start + WORK_COMMAND_SECONDS))
            self.assertIsNone(proofs[0].work_source_preflight)
            rows = await self.hub.db(self.hub.store.q, "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.operationId')=?", (request['operationId'],))
            saved = [json.loads(r['v']) for r in rows]
            events.clear()
            replay = await self.framed_connection(request, expires=clock[0]+5.5)
            self.assertTrue(replay['ok'], replay)
            self.assertEqual(replay['result'], result['result'])
            self.assertEqual(events, ['identity', 'source'])
            physical.assert_called_once()
            rows = await self.hub.db(self.hub.store.q, "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.operationId')=?", (request['operationId'],))
            self.assertEqual([json.loads(r['v']) for r in rows], saved)
            changed = {**request, 'args':{**request['args'], 'reason':'changed'}}
            refused = await self.framed_connection(changed, expires=clock[0]+5.5)
            self.assertFalse(refused['ok'], refused)
            self.assertIn('different original request', refused['error'])
            physical.assert_called_once()

    async def test_remote_inspect_revoked_during_identity_refuses_before_effect(self):
        from .test_hub_lifecycle_disclosure import HubLifecycleDisclosureTests
        agent = await self.registered()
        self.hub._native_core = object()
        identity = self.hub._caller_identity
        async def revoked(*args, **kwargs):
            result = await identity(*args, **kwargs)
            HubLifecycleDisclosureTests.revoke(self, 'inspect')
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=revoked), \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            result = await self.framed_connection({'verb':'kill',
                'args':{'session':agent['session']},'operationId':'revoked-inspect-kill'})
            self.assertFalse(result['ok'], result)
            physical.assert_not_called()
            self.assertEqual((await self.hub.db(self.hub.store.agent,agent['session']))['state'], 'ready')

    async def test_explicit_operator_attribution_retains_current_kill_checks(self):
        agent = await self.registered()
        self.hub._native_core = object()
        with patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify, \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            result = await self.framed_connection({'verb':'kill','as':'operator',
                'args':{'session':agent['session']},'operationId':'explicit-operator-kill'})
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['result'], {'killed':agent['session']})
            verify.assert_awaited_once()
            physical.assert_called_once()

    async def test_non_native_framed_kill_keeps_both_source_checks(self):
        agent = await self.registered()
        self.assertIsNone(self.hub._native_core)
        with patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify, \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            result = await self.framed_connection({'verb':'kill',
                'args':{'session':agent['session']},'operationId':'non-native-kill'})
            self.assertTrue(result['ok'], result)
            self.assertEqual(verify.await_count,2)
            physical.assert_called_once()

    async def test_direct_and_tcp_kill_keep_dispatch_verification(self):
        import asyncio
        import hashlib
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        self.hub._native_core = object()
        self.hub.operator_sha = hashlib.sha256(b'fixture-operator-secret').hexdigest()
        for tcp in (False, True):
            agent = await self.registered('tcp' if tcp else 'direct')
            request = {'verb':'kill','args':{'session':agent['session']},
                       'operationId':'unselected-kill-'+str(tcp)}
            if tcp:
                request['token'] = 'fixture-operator-secret'
            replies = []
            reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
            writer = SimpleNamespace(get_extra_info=lambda key: object(),
                write=lambda raw: replies.append(json.loads(raw)), close=Mock(), drain=AsyncMock())
            with self.subTest(tcp=tcp), \
                    patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify, \
                    patch.object(self.hub, 'harness', return_value=True) as physical:
                await self.hub.handle_conn(reader,writer,tcp=tcp)
                self.assertEqual(len(replies),1)
                self.assertTrue(replies[0]['ok'],replies)
                verify.assert_awaited_once()
                physical.assert_called_once()

    async def test_framed_kill_original_envelope_expiry_before_effect(self):
        agent = await self.registered()
        self.hub._native_core = object()
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        verify = self.binding.verify
        async def delayed():
            clock[0] += 3
            return await verify()
        with patch.object(self.binding, 'verify', side_effect=delayed), \
                patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer), \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            with self.assertRaisesRegex(AssertionError,'selected endpoint closed without a response'):
                await self.framed_connection({'verb':'kill','args':{'session':agent['session']},
                    'operationId':'expired-envelope-kill'},expires=clock[0]+2)
            physical.assert_not_called()
