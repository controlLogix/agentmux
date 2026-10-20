"""Keep connection admission and its original adoption reply in one FIFO turn."""
import asyncio
from contextlib import asynccontextmanager
import json
import secrets
import socket
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import canonical_bytes
from hub.core_endpoint import (CoreEndpoint, CoreSetupRequired, SelectedCoreRequest,
    _ReplyWriter, _mac, digest, selected_core_request)
from .test_work_source import SelectedWorkSourceFixture
from . import test_adopt_preflight as preflight
from . import test_hub_lifecycle_disclosure as disclosure


class AdoptRequestTurnTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = preflight.AdoptPreflightTests.configure_channels

    async def asyncSetUp(self):
        await preflight.AdoptPreflightTests.asyncSetUp(self)
        self.maintenance = self.hub._work_maintenance
        self.tasks = []
        self.releases = []
        self.addAsyncCleanup(self.join_tasks)

    async def join_tasks(self):
        for event in self.releases:
            event.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.wait_for(asyncio.gather(*self.tasks, return_exceptions=True), 12)

    def task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        return task

    def gate(self):
        event = asyncio.Event()
        self.releases.append(event)
        return event

    async def adoption_connection(self, *, drain=None):
        replies = []
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(self.request).encode()))
        writer = SimpleNamespace(get_extra_info=lambda key: object(),
            write=lambda raw: replies.append(json.loads(raw)), close=Mock(),
            drain=drain or AsyncMock())
        endpoint = SimpleNamespace(check=Mock(),
            route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}}))
        self.hub._selected_endpoint = endpoint
        token = selected_core_request.set(SelectedCoreRequest(
            endpoint, 'falcon', '/falcon', asyncio.current_task(), time.monotonic() + 10))
        try:
            await self.hub.handle_conn(reader, writer)
        finally:
            selected_core_request.reset(token)
        writer.close.assert_called_once()
        self.assertEqual(len(replies), 1)
        return replies[0]

    async def framed_connection(self, request, *, expires=None):
        # File custody has separate tests. Keep actual framing, Unix peer
        # admission, source verification, dispatch and response signing here.
        endpoint = object.__new__(CoreEndpoint)
        endpoint.hub = self.hub
        endpoint.tasks, endpoint.nonces = set(), {}
        endpoint.record = SimpleNamespace(raw=b'private selected fixture record')
        endpoint.value = {'key': '42' * 32}
        endpoint.route = SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}})
        endpoint.check = Mock()
        self.hub._selected_endpoint = endpoint
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        reader, writer = await asyncio.open_connection(sock=left)
        server_reader, server_writer = await asyncio.open_connection(sock=right)
        body = {'binding': digest(endpoint.record.raw), 'nonce': secrets.token_hex(32),
            'expires': time.monotonic() + 10 if expires is None else expires,
            'repository': '/falcon', 'request': request}
        task = self.task(endpoint.serve(server_reader, server_writer))
        try:
            writer.write(canonical_bytes({'core': body,
                'mac': _mac(endpoint.value['key'], body)}) + b'\n')
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), 12)
            if request.get('verb') == 'shutdown' and raw:
                # The normal client closes its original socket after checking the reply.
                decoded = json.loads(raw)
                self.assertEqual(decoded['mac'], _mac(endpoint.value['key'], decoded['core']))
                self.assertFalse(self.hub.stop.is_set())
                writer.close()
                await writer.wait_closed()
            await asyncio.wait_for(task, 3)
            self.assertTrue(raw, 'selected endpoint closed without a response')
            envelope = json.loads(raw)
            self.assertEqual(envelope['mac'], _mac(endpoint.value['key'], envelope['core']))
            return envelope['core']['response']
        finally:
            writer.close()
            server_writer.close()
            if not task.done():
                task.cancel()
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 12)
            await asyncio.gather(writer.wait_closed(), server_writer.wait_closed())

    async def test_framed_source_refusal_logs_only_closed_stage_and_category(self):
        from agentmux_contracts import ContractError
        class PrivateExceptionName(Exception):
            pass
        for failure, category in (
                (ContractError('private source details'), 'contract-refused'),
                (PrivateExceptionName('private source details'), 'other')):
            with self.subTest(category=category), \
                    patch.object(self.binding, 'verify', side_effect=failure), \
                    patch.object(self.hub, 'handle_conn', new_callable=AsyncMock) as handle, \
                    patch('hub.server.log') as log:
                with self.assertRaisesRegex(AssertionError, 'closed without a response'):
                    await self.framed_connection({'verb': 'whoami', 'args': {}})
                handle.assert_not_awaited()
                log.assert_called_once()
                label, raw = log.call_args.args
                self.assertEqual(label, 'selected core refusal')
                self.assertEqual(json.loads(raw),
                    {'stage': 'verify-source', 'category': category})
                self.assertFalse(self.hub._selected_endpoint.tasks)

    async def test_framed_refusal_logging_failure_still_joins_connection(self):
        with patch.object(self.binding, 'verify', side_effect=CoreSetupRequired()), \
                patch.object(self.hub, 'handle_conn', new_callable=AsyncMock) as handle, \
                patch('hub.server.log', side_effect=RuntimeError('private logging failure')):
            with self.assertRaisesRegex(AssertionError, 'closed without a response'):
                await self.framed_connection({'verb': 'whoami', 'args': {}})
            handle.assert_not_awaited()
            self.assertFalse(self.hub._selected_endpoint.tasks)

    async def test_framed_adoption_and_replay_verify_once_after_queue_before_identity(self):
        verify, identity = self.binding.verify, self.hub._caller_identity
        original_turn = self.maintenance.adoption_request_turn
        events = []
        queued = asyncio.Event()
        @asynccontextmanager
        async def observed(request):
            events.append('queue')
            queued.set()
            async with original_turn(request):
                events.append('admitted')
                yield
        async def verified():
            events.append('verify')
            await verify()
            events.append('verified')
        async def classified(*args, **kwargs):
            events.append('identity')
            return await identity(*args, **kwargs)
        with patch.object(self.maintenance, 'adoption_request_turn', observed), \
                patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, '_caller_identity', side_effect=classified):
            results = []
            for _ in range(2):
                events.clear()
                queued.clear()
                async with self.maintenance._serialized():
                    task = self.task(self.framed_connection(self.request))
                    await asyncio.wait_for(queued.wait(), 5)
                    self.assertEqual(events, ['queue'])
                    self.assertEqual(len(self.hub._authenticated_callers), 0)
                result = await asyncio.wait_for(task, 12)
                self.assertTrue(result['ok'], result)
                self.assertEqual(events, ['queue', 'admitted', 'verify', 'verified', 'identity'])
                self.assertEqual(result['operationId'], self.request['operationId'])
                results.append(result)
                row = await self.hub.db(self.hub.store.agent, result['result']['session'])
                effects = [r for r in self.submitted
                    if r['contractId'] in ('federation-work-register', 'federation-work-state')]
                if len(results) == 1:
                    original_row, original_effects = row, effects
                else:
                    self.assertEqual(row, original_row)
                    self.assertEqual(effects, original_effects)
            self.assertEqual(results[0], results[1])
            self.assertEqual(original_row['generation'], 1)

    async def test_framed_queued_source_change_and_register_revocation_refuse_effect(self):
        original_turn = self.maintenance.adoption_request_turn
        queued = asyncio.Event()
        @asynccontextmanager
        async def observed(request):
            queued.set()
            async with original_turn(request):
                yield
        previous = self.hub.cfg.get('nats_url')
        with patch.object(self.maintenance, 'adoption_request_turn', observed):
            for change in ('source', 'register-grant'):
                with self.subTest(change=change):
                    queued.clear()
                    try:
                        async with self.maintenance._serialized():
                            task = self.task(self.framed_connection(self.request))
                            await asyncio.wait_for(queued.wait(), 5)
                            if change == 'source':
                                self.hub.cfg['nats_url'] = 'nats://changed.invalid'
                            else:
                                disclosure.HubLifecycleDisclosureTests.revoke(self, 'register')
                        result = await asyncio.wait_for(task, 12)
                        self.assertFalse(result['ok'], result)
                        # Restore fixture mode before using the guarded DB reader
                        # to check that the refused call made no agent.
                        if previous is None:
                            self.hub.cfg.pop('nats_url', None)
                        else:
                            self.hub.cfg['nats_url'] = previous
                        self.assertIsNone(await self.hub.db(
                            self.hub.store.agent, 'falcon-worker-preflight'))
                        self.assertIsNone(self.maintenance._request_turn)
                    finally:
                        if previous is None:
                            self.hub.cfg.pop('nats_url', None)
                        else:
                            self.hub.cfg['nats_url'] = previous

    async def test_framed_nonadopt_keeps_endpoint_verification_before_authentication(self):
        events = []
        verify, authenticate = self.binding.verify, self.hub.authenticate_caller
        async def verified():
            events.append('verify')
            await verify()
            events.append('verified')
        async def authenticated(*args, **kwargs):
            events.append('authenticate')
            return await authenticate(*args, **kwargs)
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, 'authenticate_caller', side_effect=authenticated):
            result = await self.framed_connection({'verb': 'whoami', 'args': {}})
        self.assertTrue(result['ok'], result)
        self.assertEqual(events[:3], ['verify', 'verified', 'authenticate'])
        self.assertIsNone(self.maintenance._request_turn)

    async def test_selected_ping_verifies_before_proof_without_repeating_remote_read(self):
        from dataclasses import replace
        events = []
        verify, authenticate = self.binding.verify, self.hub.authenticate_caller
        async def verified():
            events.append('verify')
            if 'proof' in events:
                # Model a second remote read exhausting this original proof.
                await asyncio.sleep(.25)
            return await verify()
        async def authenticated(*args, **kwargs):
            proof = await authenticate(*args, **kwargs)
            events.append('proof')
            self.hub._authenticated_callers[proof] = replace(
                self.hub._authenticated_callers[proof], expires_monotonic=time.monotonic() + .2)
            return proof
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch.object(self.hub, 'identify_qualified', wraps=self.hub.identify_qualified) as final_identity:
            result = await self.framed_connection({'verb': 'ping', 'args': {}})
        self.assertTrue(result['ok'], result)
        self.assertEqual(events, ['verify', 'proof'])
        self.assertTrue(result['result']['lifecycleOperationIds'])
        self.assertEqual(final_identity.call_count, 2)
        self.assertFalse(self.hub._authenticated_callers)

    async def test_selected_shutdown_avoids_duplicate_read_within_original_envelope(self):
        events = []
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        envelope_expires = clock[0] + .5
        verify, authenticate = self.binding.verify, self.hub.authenticate_caller
        classify = self.hub.identify_qualified
        classifications = []
        closed = None
        async def verified():
            events.append('verify')
            clock[0] += .15
            return await verify()
        async def authenticated(*args, **kwargs):
            proof = await authenticate(*args, **kwargs)
            events.append('proof')
            admitted = self.hub._authenticated_callers[proof]
            self.assertEqual(admitted.expires_monotonic, envelope_expires)
            self.assertIsNone(admitted.work_source_preflight)
            return proof
        def classified(pid):
            classifications.append(pid)
            # Both original classifications consume the selected envelope budget.
            clock[0] += .15
            return classify(pid)
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch.object(self.hub, 'identify_qualified', side_effect=classified), \
                patch('hub.server.time', timer), \
                patch('hub.core_endpoint.time', timer), \
                patch('hub.server.log') as log:
            try:
                result = await self.framed_connection(
                    {'verb': 'shutdown', 'args': {}}, expires=envelope_expires)
            except AssertionError as error:
                closed = error
        self.assertEqual(len(classifications), 2)
        if closed is not None or not result['ok']:
            stages = [json.loads(call.args[1])['stage'] for call in log.call_args_list
                if call.args[0] == 'authenticated work refusal']
            self.assertEqual(stages, ['current-after-expired'])
        if closed is not None:
            raise closed
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['result'], {'stopping': True})
        self.assertEqual(events, ['proof', 'verify'])
        self.assertEqual(len(classifications), 2)
        self.assertTrue(self.hub.stop.is_set())
        self.assertFalse(self.hub._authenticated_callers)

    async def test_managed_and_attributed_selected_ping_keep_dispatch_verification(self):
        for identity, attribution in ((('falcon-worker-existing', True), None),
                                      ((None, False), 'falcon-worker-existing')):
            request = {'verb': 'ping', 'args': {}}
            if attribution is not None:
                request['as'] = attribution
            with self.subTest(attribution=attribution), \
                    patch.object(self.hub, 'identify_qualified', return_value=identity), \
                    patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
                result = await self.framed_connection(request)
                self.assertTrue(result['ok'], result)
                self.assertEqual(verify.await_count, 2)

    async def test_selected_shutdown_preserves_operator_and_attribution_guards(self):
        for identity, attribution, allowed, reads in (
                ((None, False), None, True, 1),
                ((None, False), 'operator', True, 1),
                (('falcon-worker-existing', True), None, False, 1),
                ((None, False), 'falcon-worker-existing', False, 1),
                (('falcon-worker-existing', True), 'operator', False, 0)):
            self.hub.stop.clear()
            request = {'verb': 'shutdown', 'args': {}}
            if attribution is not None:
                request['as'] = attribution
            with self.subTest(identity=identity, attribution=attribution), \
                    patch.object(self.hub, 'identify_qualified', return_value=identity), \
                    patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
                result = await self.framed_connection(request)
                self.assertEqual(result['ok'], allowed, result)
                self.assertEqual(verify.await_count, reads)
                self.assertEqual(self.hub.stop.is_set(), allowed)
                self.assertFalse(self.hub._authenticated_callers)

    async def test_unselected_and_tcp_shutdown_keep_dispatch_verification(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp), \
                    patch.object(self.hub, '_caller_identity', return_value=('operator', 'operator')), \
                    patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
                proof = await self.hub.authenticate_caller(
                    {'verb': 'shutdown', 'args': {}}, self.writer, tcp)
                verify.assert_not_awaited()
                self.assertIsNone(self.hub._authenticated_callers[proof].work_source_preflight)
                token = self.hub._authenticated_caller_context.set(proof)
                try:
                    self.assertEqual(await self.hub.dispatch('shutdown', {}, 'operator'),
                        {'stopping': True})
                    verify.assert_awaited_once()
                finally:
                    self.hub._authenticated_caller_context.reset(token)
                    self.hub._authenticated_callers.pop(proof)

    async def test_selected_shutdown_revoked_source_after_identity_refuses(self):
        identity = self.hub._caller_identity
        async def revoked(*args, **kwargs):
            result = await identity(*args, **kwargs)
            disclosure.HubLifecycleDisclosureTests.revoke(self, 'inspect')
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=revoked), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
            result = await self.framed_connection({'verb': 'shutdown', 'args': {}})
        self.assertFalse(result['ok'], result)
        verify.assert_awaited_once()
        self.assertFalse(self.hub.stop.is_set())
        self.assertFalse(self.hub._authenticated_callers)

    async def test_selected_shutdown_wrong_uid_refuses_before_remote_read(self):
        import os
        with patch.object(self.hub, 'peer', return_value=(123, os.getuid() + 1)), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
            result = await self.framed_connection({'verb': 'shutdown', 'args': {}})
        self.assertFalse(result['ok'], result)
        self.assertIn('wrong uid', result['error'])
        verify.assert_not_awaited()
        self.assertFalse(self.hub.stop.is_set())

    async def test_selected_shutdown_changed_final_identity_refuses(self):
        with patch.object(self.hub, 'identify_qualified',
                side_effect=[(None, False), ('falcon-worker-existing', True)]) as classify:
            result = await self.framed_connection({'verb': 'shutdown', 'args': {}})
        self.assertFalse(result['ok'], result)
        self.assertEqual(classify.call_count, 2)
        self.assertIn('authenticated work request changed or expired', result['error'])
        self.assertFalse(self.hub.stop.is_set())
        self.assertFalse(self.hub._authenticated_callers)

    async def test_selected_shutdown_cancelled_source_read_joins_original_workers(self):
        entered, release = asyncio.Event(), self.gate()
        prove = self.binding._prove_current
        workers = []
        async def held(*args, **kwargs):
            workers.append(asyncio.current_task())
            result = await prove(*args, **kwargs)
            entered.set()
            await release.wait()
            return result
        with patch.object(self.binding, '_prove_current', side_effect=held):
            task = self.task(self.framed_connection({'verb': 'shutdown', 'args': {}}))
            try:
                await asyncio.wait_for(entered.wait(), 3)
                task.cancel()
                delivered = asyncio.Event()
                asyncio.get_running_loop().call_soon(delivered.set)
                await delivered.wait()
                self.assertFalse(task.done())
                self.assertTrue(any(not worker.done() for worker in workers))
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(asyncio.shield(task), 5)
                self.assertTrue(all(worker.done() for worker in workers))
                self.assertFalse(self.binding.pending)
                self.assertFalse(self.hub.stop.is_set())
                self.assertFalse(self.hub._authenticated_callers)
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 8)

    async def test_selected_shutdown_source_change_during_identity_refuses_proof(self):
        identity = self.hub._caller_identity
        previous = self.hub.cfg.get('nats_url')
        async def changed(*args, **kwargs):
            result = await identity(*args, **kwargs)
            self.hub.cfg['nats_url'] = 'nats://changed.invalid'
            return result
        try:
            with patch.object(self.hub, '_caller_identity', side_effect=changed):
                result = await self.framed_connection({'verb': 'shutdown', 'args': {}})
            self.assertFalse(result['ok'], result)
            self.assertIn('work_source_binding_refused', result['error'])
            self.assertFalse(self.hub.stop.is_set())
            self.assertFalse(self.hub._authenticated_callers)
        finally:
            if previous is None:
                self.hub.cfg.pop('nats_url', None)
            else:
                self.hub.cfg['nats_url'] = previous

    async def test_unselected_and_tcp_ping_keep_dispatch_verification(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp), \
                    patch.object(self.hub, '_caller_identity', return_value=('operator', 'operator')), \
                    patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
                proof = await self.hub.authenticate_caller({'verb': 'ping', 'args': {}}, self.writer, tcp)
                verify.assert_not_awaited()
                self.assertIsNone(self.hub._authenticated_callers[proof].work_source_preflight)
                token = self.hub._authenticated_caller_context.set(proof)
                try:
                    result = await self.hub.dispatch('ping', {}, 'operator')
                    self.assertTrue(result['lifecycleOperationIds'])
                    verify.assert_awaited_once()
                finally:
                    self.hub._authenticated_caller_context.reset(token)
                    self.hub._authenticated_callers.pop(proof)

    async def test_selected_ping_source_change_during_identity_refuses_proof(self):
        identity = self.hub._caller_identity
        previous = self.hub.cfg.get('nats_url')
        async def changed(*args, **kwargs):
            result = await identity(*args, **kwargs)
            self.hub.cfg['nats_url'] = 'nats://changed.invalid'
            return result
        try:
            with patch.object(self.hub, '_caller_identity', side_effect=changed):
                result = await self.framed_connection({'verb': 'ping', 'args': {}})
            self.assertFalse(result['ok'], result)
            self.assertIn('work_source_binding_refused', result['error'])
            self.assertFalse(self.hub._authenticated_callers)
        finally:
            if previous is None:
                self.hub.cfg.pop('nats_url', None)
            else:
                self.hub.cfg['nats_url'] = previous

    async def test_queue_precedes_proof_and_same_id_replay_preserves_registration(self):
        queued = asyncio.Event()
        original_turn = self.maintenance.adoption_request_turn
        @asynccontextmanager
        async def observed(request):
            queued.set()
            async with original_turn(request):
                yield
        with patch.object(self.maintenance, 'adoption_request_turn', observed), \
                patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authenticate:
            async with self.maintenance._serialized():
                task = self.task(self.adoption_connection())
                await asyncio.wait_for(queued.wait(), 3)
                authenticate.assert_not_awaited()
                self.assertEqual(len(self.hub._authenticated_callers), 0)
            first = await asyncio.wait_for(task, 10)
        self.assertTrue(first['ok'], first)
        session = first['result']['session']
        before = await self.hub.db(self.hub.store.agent, session)
        effects = [r for r in self.submitted
            if r['contractId'] in ('federation-work-register', 'federation-work-state')]
        second = await asyncio.wait_for(self.adoption_connection(), 10)
        self.assertTrue(second['ok'], second)
        self.assertEqual(second['result'], first['result'])
        self.assertEqual(second['operationId'], self.request['operationId'])
        self.assertEqual(await self.hub.db(self.hub.store.agent, session), before)
        self.assertEqual([r for r in self.submitted
            if r['contractId'] in ('federation-work-register', 'federation-work-state')], effects)
        self.assertEqual(before['generation'], 1)
        self.assertIsNone(self.maintenance._request_turn)

    async def test_unrelated_inherited_task_waits_through_final_check_and_reply(self):
        final_entered, read_entered, read_queued = asyncio.Event(), asyncio.Event(), asyncio.Event()
        release_final, release_reply = self.gate(), self.gate()
        reply_entered = asyncio.Event()
        original = self.hub._check_work_targets
        background = None
        async def read():
            read_queued.set()
            async with self.maintenance.observation_read_turn():
                read_entered.set()
        async def final():
            nonlocal background
            # Created in the connection context, but never granted child custody.
            background = self.task(read())
            await read_queued.wait()
            final_entered.set()
            await release_final.wait()
            await original()
        async def drain():
            reply_entered.set()
            await release_reply.wait()
        with patch.object(self.hub, '_check_work_targets', side_effect=final):
            connection = self.task(self.adoption_connection(drain=drain))
            try:
                await asyncio.wait_for(final_entered.wait(), 10)
            except TimeoutError:
                if connection.done():
                    self.fail(f'Connection finished before final check: {connection.result()!r}')
                raise
            self.assertFalse(read_entered.is_set())
            release_final.set()
            await asyncio.wait_for(reply_entered.wait(), 5)
            self.assertFalse(read_entered.is_set())
            release_reply.set()
            result = await asyncio.wait_for(connection, 5)
        self.assertTrue(result['ok'], result)
        await asyncio.wait_for(background, 3)
        self.assertTrue(read_entered.is_set())
        self.assertIsNone(self.maintenance._request_turn)

    async def test_cancelled_queued_connection_never_authenticates_or_releases_holder(self):
        queued = asyncio.Event()
        original_turn = self.maintenance.adoption_request_turn
        @asynccontextmanager
        async def observed(request):
            queued.set()
            async with original_turn(request):
                yield
        with patch.object(self.maintenance, 'adoption_request_turn', observed), \
                patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authenticate:
            async with self.maintenance._serialized():
                task = self.task(self.adoption_connection())
                await asyncio.wait_for(queued.wait(), 3)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 3)
                self.assertTrue(self.maintenance._lock.locked())
                authenticate.assert_not_awaited()
        self.assertIsNone(self.maintenance._request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_cancellation_joins_original_child_before_releasing_turn(self):
        entered, child_finished = asyncio.Event(), asyncio.Event()
        release = self.gate()
        original = self.maintenance.confirm_result
        children = []
        async def confirm(*args, **kwargs):
            children.append(asyncio.current_task())
            entered.set()
            await release.wait()
            result = await original(*args, **kwargs)
            child_finished.set()
            return result
        with patch.object(self.maintenance, 'confirm_result', side_effect=confirm):
            task = self.task(self.adoption_connection())
            await asyncio.wait_for(entered.wait(), 10)
            task.cancel()
            yielded = asyncio.Event()
            asyncio.get_running_loop().call_soon(yielded.set)
            await yielded.wait()
            self.assertFalse(task.done())
            self.assertIs(self.maintenance._request_turn['child'], children[0])
            self.assertTrue(self.maintenance._lock.locked())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 8)
        self.assertTrue(child_finished.is_set())
        self.assertTrue(children[0].done())
        self.assertIsNone(self.maintenance._request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_current_register_revocation_refuses_and_releases_reservation(self):
        original = self.hub._caller_identity
        async def revoked(*args, **kwargs):
            result = await original(*args, **kwargs)
            disclosure.HubLifecycleDisclosureTests.revoke(self, 'register')
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=revoked):
            result = await asyncio.wait_for(self.adoption_connection(), 10)
        self.assertFalse(result['ok'])
        self.assertIsNone(await self.hub.db(self.hub.store.agent, 'falcon-worker-preflight'))
        self.assertIsNone(self.maintenance._request_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_selected_envelope_expired_in_queue_never_authenticates(self):
        # Exercise real framing and Unix peers. Endpoint file custody is outside
        # this fixture; its existing check is represented by a closed stub.
        endpoint = object.__new__(CoreEndpoint)
        endpoint.hub = self.hub
        endpoint.tasks, endpoint.nonces = set(), {}
        endpoint.record = SimpleNamespace(raw=b'private selected fixture record')
        endpoint.value = {'key': '42' * 32}
        endpoint.route = SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}})
        endpoint.check = Mock()
        self.hub._selected_endpoint = endpoint
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        client_reader, client_writer = await asyncio.open_connection(sock=left)
        server_reader, server_writer = await asyncio.open_connection(sock=right)
        queued, expired = asyncio.Event(), asyncio.Event()
        original_turn = self.maintenance.adoption_request_turn
        @asynccontextmanager
        async def observed(request):
            queued.set()
            async with original_turn(request):
                yield
        deadline = time.monotonic() + 5
        body = {'binding': digest(endpoint.record.raw), 'nonce': '7' * 64,
            'expires': deadline, 'repository': '/falcon', 'request': self.request}
        timer = None
        try:
            with patch.object(self.maintenance, 'adoption_request_turn', observed), \
                    patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authenticate:
                async with self.maintenance._serialized():
                    task = self.task(endpoint.serve(server_reader, server_writer))
                    client_writer.write(canonical_bytes({'core': body,
                        'mac': _mac(endpoint.value['key'], body)}) + b'\n')
                    await client_writer.drain()
                    await asyncio.wait_for(queued.wait(), 4)
                    authenticate.assert_not_awaited()
                    timer = asyncio.get_running_loop().call_later(
                        max(0, deadline - time.monotonic()) + .02, expired.set)
                    await asyncio.wait_for(expired.wait(), 6)
                await asyncio.wait_for(task, 5)
                authenticate.assert_not_awaited()
            self.assertFalse(any(r['contractId'] == 'federation-work-register'
                for r in self.submitted))
            self.assertEqual(len(self.hub._authenticated_callers), 0)
            self.assertIsNone(self.maintenance._request_turn)
            self.assertFalse(self.maintenance._lock.locked())
        finally:
            if timer is not None:
                timer.cancel()
            client_writer.close()
            server_writer.close()
            await asyncio.gather(client_writer.wait_closed(), server_writer.wait_closed())

    async def test_selected_expiry_during_classification_does_not_mint_proof(self):
        deadline = time.monotonic() + 5
        endpoint = SimpleNamespace(check=Mock(),
            route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}}))
        self.hub._selected_endpoint = endpoint
        classified, expired = asyncio.Event(), asyncio.Event()
        original = self.hub._caller_identity
        timer = None
        async def held(*args, **kwargs):
            nonlocal timer
            result = await original(*args, **kwargs)
            self.assertLess(time.monotonic(), deadline)
            classified.set()
            timer = asyncio.get_running_loop().call_later(
                deadline - time.monotonic() + .02, expired.set)
            await expired.wait()
            return result
        token = selected_core_request.set(SelectedCoreRequest(
            endpoint, 'falcon', '/falcon', asyncio.current_task(), deadline))
        try:
            with patch.object(self.hub, '_caller_identity', side_effect=held):
                with self.assertRaises(CoreSetupRequired):
                    # No new task: selected caller context belongs to this task.
                    async with asyncio.timeout(7):
                        await self.hub.authenticate_caller(self.request, self.writer, False)
            self.assertTrue(classified.is_set())
            self.assertEqual(len(self.hub._authenticated_callers), 0)
        finally:
            selected_core_request.reset(token)
            if timer is not None:
                timer.cancel()

    async def test_final_writer_refuses_expired_original_envelope(self):
        endpoint = SimpleNamespace(check=Mock(), value={'key': '42' * 32})
        underlying = SimpleNamespace(write=Mock())
        deadline = time.monotonic() + .02
        request = {'expires': deadline, 'nonce': '7' * 64,
            'binding': 'b' * 64, 'request': self.request}
        writer = _ReplyWriter(endpoint, underlying, request, None)
        expired = asyncio.Event()
        timer = asyncio.get_running_loop().call_later(.04, expired.set)
        try:
            await asyncio.wait_for(expired.wait(), 1)
            self.assertGreaterEqual(time.monotonic(), deadline)
            with self.assertRaises(CoreSetupRequired):
                writer.write(canonical_bytes({'ok': True, 'result': {}}))
            underlying.write.assert_not_called()
        finally:
            timer.cancel()

    async def test_selected_proof_never_outlives_original_envelope(self):
        deadline = time.monotonic() + 5
        endpoint = SimpleNamespace(check=Mock(),
            route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}}))
        self.hub._selected_endpoint = endpoint
        token = selected_core_request.set(SelectedCoreRequest(
            endpoint, 'falcon', '/falcon', asyncio.current_task(), deadline))
        try:
            proof = await self.hub.authenticate_caller(self.request, self.writer, False)
            admitted = self.hub._authenticated_callers[proof]
            self.assertLessEqual(admitted.expires_monotonic, deadline)
            self.assertGreater(admitted.expires_monotonic, time.monotonic())
        finally:
            selected_core_request.reset(token)
