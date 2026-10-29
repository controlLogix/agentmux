"""Actual Hub authentication and signed owner work RPC recovery."""
import asyncio
from contextvars import ContextVar
from datetime import timedelta
import hashlib
import json
import socket
import threading
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.test_service import _Clock
from identity.test_authority import NOW
from hub import cli
from hub.server import Hub
from .work_rpc import WorkRpc
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_local_work_client as support
from identity.work_client import WORK_COMMAND_SECONDS


class WorkRpcTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    open_client = support.LocalWorkClientTests.open_client
    session_for = support.LocalWorkClientTests.session_for
    agent = support.LocalWorkClientTests.agent
    open_both_repositories = support.LocalWorkClientTests.open_both_repositories

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.local_work_client',
                'capability_owner.work_rpc', 'hub.server'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.caller = 'operator'
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('actual-work-rpc-proof', default=None)
        self.hub._work_source_binding = None
        original_db = self.hub.db
        async def checked_db(function, *args, **kwargs):
            if function in (self.store.work_create, self.store.claim, self.store.heartbeat,
                    self.store.release, self.store.cancel, self.store.claim_path, self.store.work):
                raise AssertionError('RPC bypassed the signed work owner')
            if function in (self.store.q, self.store.q1) and args and 'work_items' in args[0].lower():
                raise AssertionError('RPC queried raw work SQL')
            return await original_db(function, *args, **kwargs)
        self.hub.db = checked_db
        await self.open_client()
        self.install_client()
        self.hub.fed = SimpleNamespace(enabled=False, local_event=AsyncMock())
        self.args = {'to': 'role:falcon/worker', 'title': 'Original', 'federate': True}

    def install_client(self):
        self.hub._work_storage_commands, self.hub._local_work_commands = self.commands, self.client
        self.hub._work_rpc = WorkRpc(self.hub, self.commands, self.client)

    async def packet(self, verb='work_add', args=None, *, operation_id='original-rpc',
            token='operator-secret', discard=False, override=None):
        request = {'verb': verb, 'args': self.args if args is None else args, 'token': token}
        if operation_id is not None:
            request['operationId'] = operation_id
        if override is not None:
            request['as'] = override
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        replies = []
        writer = SimpleNamespace(write=Mock(side_effect=lambda raw: replies.append(json.loads(raw))),
            drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        original = asyncio.create_task(self.hub.handle_conn(reader, writer, tcp=True))
        await original
        writer.close.assert_called_once()
        self.assertEqual(len(replies), 1)
        return None if discard else replies[0]

    def active(self):
        return self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")

    def mutations(self, action='create'):
        return [request for request in self.submitted if request['contractId'] == 'federation-work-' + action]

    async def selected_create(self, repository, arguments, *, operation_id='selected-original'):
        request = {'verb': 'work_add', 'args': arguments, 'operationId': operation_id,
            'token': 'operator-secret'}
        proof = await self.hub.authenticate_caller(request, object(), True)
        context = self.hub._authenticated_caller_context.set(proof)
        rpc = self.hub._work_rpc
        try:
            result = await rpc.execute(proof, 'work_add', arguments, 'operator', repository=repository)
            await rpc.complete(result)
            rpc.check_response(result, finish=True)
            await rpc.delivered()
            return result
        finally:
            rpc.abort()
            self.hub._authenticated_caller_context.reset(context)

    async def test_selected_completed_replay_refuses_foreign_context_and_preserves_original(self):
        await self.open_both_repositories()
        self.install_client()
        arguments = {**self.args, 'to': 'role:other/worker'}
        original = await self.selected_create('other', arguments)
        retained = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'")
        with self.assertRaises(ContractError):
            await self.selected_create('falcon', arguments)
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'"), retained)
        self.assertEqual(await self.selected_create('other', arguments), original)
        self.assertEqual(len(self.mutations()), 1)

    async def test_selected_pending_rpc_refusal_keeps_foreign_unsubmitted_reservation(self):
        await self.open_both_repositories()
        self.install_client()
        arguments = {**self.args, 'to': 'role:other/worker'}
        request = {'verb': 'work_add', 'args': arguments, 'operationId': 'selected-original',
            'token': 'operator-secret'}
        proof = await self.hub.authenticate_caller(request, object(), True)
        context = self.hub._authenticated_caller_context.set(proof)
        try:
            admitted = self.hub._admit_local_work('work_add', arguments, 'operator')
            bindings = [self.commands._binding(enrollment)
                for _, enrollment in self.commands._select('operator', 'create', 'other')]
            await self.commands._owned_db(self.hub._work_rpc._completion.reserve,
                operation_id='selected-original', request_digest=admitted.request_digest,
                principal={'authenticatedCaller': 'operator', 'caller': 'operator'},
                verb='work_add', arguments=arguments, bindings=bindings)
        finally:
            self.hub._authenticated_caller_context.reset(context)
        retained = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'")
        self.assertEqual(len(retained), 1)
        with self.assertRaises(ContractError):
            await self.selected_create('falcon', arguments)
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'"), retained)
        self.assertEqual(self.mutations(), [])
        result = await self.selected_create('other', arguments)
        self.assertEqual(result['repo'], 'other')
        self.assertEqual(len(self.mutations()), 1)

    async def test_selected_completed_replay_still_checks_current_grant(self):
        original = await self.selected_create('falcon', self.args)
        state = strict_loads(self.js.messages[-1].data)
        next(g for g in state['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-create'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        with self.assertRaises(ContractError):
            await self.selected_create('falcon', self.args)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.store.work(original['id'])['title'], original['title'])

    async def test_selected_rpc_rejects_non_plain_repository_before_reservation(self):
        class MutableRepository(str):
            pass
        for repository in ('', True, ['falcon'], MutableRepository('falcon')):
            with self.subTest(repository=repr(repository)), self.assertRaises(ContractError):
                await self.selected_create(repository, self.args)
        self.assertEqual(self.submitted, [])
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:%'"), [])

    async def test_adapter_consumes_actual_proof_and_retains_completed_receipt(self):
        request = {'verb': 'work_add', 'args': self.args, 'operationId': 'adapter-original',
            'token': 'operator-secret'}
        proof = await self.hub.authenticate_caller(request, object(), True)
        context = self.hub._authenticated_caller_context.set(proof)
        rpc = self.hub._work_rpc
        try:
            result = await rpc.execute(proof, 'work_add', self.args, 'operator')
            self.assertFalse(rpc.replayed())
            self.assertEqual(rpc.operation_id, 'adapter-original')
            await rpc.complete(result)
            self.assertEqual(rpc.check_response(result, finish=True), result)
            await rpc.delivered()
            self.assertEqual(self.active(), [])
            self.assertEqual(len(self.store.q(
                "SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:completed:%'")), 1)
        finally:
            rpc.abort()
            self.hub._authenticated_caller_context.reset(context)

    async def test_original_authenticated_arguments_cannot_change_during_target_await(self):
        arguments = dict(self.args)
        request = {'verb': 'work_add', 'args': arguments, 'operationId': 'immutable-original',
            'token': 'operator-secret'}
        proof = await self.hub.authenticate_caller(request, object(), True)
        context = self.hub._authenticated_caller_context.set(proof)
        rpc = self.hub._work_rpc
        original = self.hub._work_on_behalf
        async def changed(admitted):
            arguments['title'] = 'Substituted after authentication'
            await asyncio.sleep(0)
            return await original(admitted)
        try:
            with patch.object(self.hub, '_work_on_behalf', side_effect=changed):
                result = await rpc.execute(proof, 'work_add', arguments, 'operator')
            self.assertEqual(result['title'], 'Original')
            await rpc.complete(result)
            rpc.check_response(result, finish=True)
            await rpc.delivered()
            self.assertEqual(self.mutations()[0]['payload']['input']['title'], 'Original')
        finally:
            rpc.abort()
            self.hub._authenticated_caller_context.reset(context)

    async def test_actual_drained_discarded_response_replays_original_after_restart_and_later_write(self):
        self.assertIsNone(await self.packet(discard=True))
        original = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(self.active(), [])
        await self.open_client()
        self.install_client()
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Later write')
        recovered = await self.packet()
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result'], original)
        self.assertEqual(recovered['operationId'], 'original-rpc')
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)
        self.assertEqual(self.active(), [])

    async def test_identical_new_ids_and_raw_no_id_calls_remain_distinct(self):
        first = await self.packet(operation_id='first')
        second = await self.packet(operation_id='second')
        third = await self.packet(operation_id=None)
        fourth = await self.packet(operation_id=None)
        for response in (first, second, third, fourth):
            self.assertTrue(response['ok'], response)
            self.assertTrue(response['operationId'])
        self.assertEqual(len({r['result']['id'] for r in (first, second, third, fourth)}), 4)
        self.assertNotEqual(third['operationId'], fourth['operationId'])

    async def test_reused_id_refuses_changed_arguments_actor_and_selected_source(self):
        first = await self.packet()
        self.assertTrue(first['ok'], first)
        changed = await self.packet(args={**self.args, 'title': 'Substituted'})
        self.assertFalse(changed['ok'], changed)
        self.assertFalse((await self.packet(token='invalid-secret'))['ok'])
        selected = strict_loads(self.session._work_enrollment)
        selected['workCommands']['resourceRef']['revision'] += 1
        self.session._work_enrollment = canonical_bytes(selected)
        changed = await self.packet()
        self.assertFalse(changed['ok'], changed)
        self.assertNotIn(first['result']['id'], canonical_bytes(changed).decode())
        self.assertEqual(len(self.mutations()), 1)

    async def test_current_original_grant_revocation_refuses_completed_replay(self):
        original = await self.packet()
        self.assertTrue(original['ok'], original)
        state = strict_loads(self.js.messages[-1].data)
        next(g for g in state['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-create'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        refused = await self.packet()
        self.assertFalse(refused['ok'], refused)
        self.assertNotIn(original['result']['id'], canonical_bytes(refused).decode())
        self.assertEqual(len(self.mutations()), 1)

    async def test_notification_rechecks_owner_validity_at_commit(self):
        await self.agent(maximum=2)
        self.install_client()
        self.hub._legacy_identity = None
        self.hub._notify_work_owner = Hub._notify_work_owner.__get__(self.hub, Hub)
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        row = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Original protected result')
        self.store.claim(self.caller, work_id=row['id'])
        original = self.hub._current_identity_target
        advanced = []
        class Expired(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=WORK_COMMAND_SECONDS + 1)
        async def expire_after_notification_identity(*args, **kwargs):
            result = await original(*args, **kwargs)
            timer = patch('capability_owner.legacy_work_client.datetime', Expired)
            timer.start()
            self.addCleanup(timer.stop)
            advanced.append(True)
            return result
        with patch.object(self.hub, '_current_identity_target', side_effect=expire_after_notification_identity):
            response = await self.packet('release', {'work_id': row['id'], 'outcome': 'done',
                'result': 'Private exact result'}, token='agent-secret', operation_id='notification-expiry')
        self.assertEqual(advanced, [True], response)
        self.assertFalse(response['ok'], response)
        messages = self.store.q("SELECT id FROM messages WHERE kind='result' AND work_id=?", (row['id'],))
        self.assertEqual(messages, [], 'A result notification committed after its owner reply expired')
        self.assertEqual(len(self.active()), 1)
        self.assertEqual(self.store.q(
            "SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:completed:%'"), [])

    async def test_lost_owner_response_retains_original_and_recovers_without_resubmission(self):
        self.drop_after = 'federation-work-create'
        uncertain = await self.packet()
        self.assertFalse(uncertain['ok'], uncertain)
        original = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(len(self.active()), 1)
        recovered = await self.packet()
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result'], original)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.active(), [])

    async def test_actual_agent_claim_heartbeat_path_release_and_retry(self):
        await self.agent(maximum=2)
        self.install_client()
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Claim original')
        claimed = await self.packet('claim', {'work_id': row['id']}, token='agent-secret', operation_id='claim-one')
        self.assertTrue(claimed['ok'], claimed)
        self.assertEqual(claimed['result']['claimed']['id'], row['id'])
        heartbeat = await self.packet('heartbeat', {}, token='agent-secret', operation_id='heartbeat-one')
        self.assertTrue(heartbeat['ok'], heartbeat)
        self.assertEqual(heartbeat['result'], {'renewed': 1})
        path = await self.packet('claim_path', {'path': 'src/original.py', 'work_id': row['id']},
            token='agent-secret', operation_id='path-one')
        self.assertTrue(path['ok'], path)
        release_args = {'work_id': row['id'], 'outcome': 'done', 'result': 'Original raw result'}
        with patch.object(self.hub, '_notify_work_owner', new=AsyncMock()) as notify:
            released = await self.packet('release', release_args, token='agent-secret', operation_id='release-one')
            self.assertTrue(released['ok'], released)
            recovered = await self.packet('release', release_args, token='agent-secret', operation_id='release-one')
            self.assertEqual(recovered['result'], released['result'])
            notify.assert_awaited_once()
        self.assertNotIn('children', released['result'])
        self.assertEqual(self.active(), [])

    async def test_qualified_ping_advertises_stable_operation_recovery(self):
        response = await self.packet('ping', {}, operation_id=None)
        self.assertTrue(response['ok'], response)
        self.assertIs(response['result']['workOperationIds'], True)

    async def test_unqualified_hub_refuses_explicit_recovery_id_before_mutation(self):
        self.hub._work_rpc = None
        response = await self.packet()
        self.assertFalse(response['ok'], response)
        self.assertIn('does not support work operation recovery IDs', response['error'])
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        self.assertEqual(self.submitted, [])

    async def test_malformed_unsubmitted_calls_do_not_exhaust_pending_rpc_capacity(self):
        for index in range(32):
            response = await self.packet(args={**self.args, 'title': ''}, operation_id='malformed-' + str(index))
            self.assertFalse(response['ok'], response)
        valid = await self.packet(operation_id='valid-after-malformed')
        self.assertTrue(valid['ok'], valid)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.active(), [])
        self.assertEqual(self.store.q(
            "SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:pending:%'"), [])

    async def test_rpc_close_cancellation_joins_original_invocation_before_base_close(self):
        entered, release = asyncio.Event(), asyncio.Event()
        rpc = self.hub._work_rpc
        async def invoke():
            request = {'verb': 'work_add', 'args': self.args, 'operationId': 'closing-original',
                'token': 'operator-secret'}
            proof = await self.hub.authenticate_caller(request, object(), True)
            context = self.hub._authenticated_caller_context.set(proof)
            try:
                result = await rpc.execute(proof, 'work_add', self.args, 'operator')
                entered.set()
                await release.wait()
                await rpc.complete(result)
                rpc.check_response(result, finish=True)
                await rpc.delivered()
            finally:
                rpc.abort()
                self.hub._authenticated_caller_context.reset(context)
        invocation = asyncio.create_task(invoke())
        closing = None
        try:
            await asyncio.wait_for(entered.wait(), 5)
            closing = asyncio.create_task(rpc.close(timeout=None))
            await asyncio.sleep(.02)
            closing.cancel()
            await asyncio.sleep(.02)
            self.assertFalse(closing.done())
            self.assertFalse(invocation.done())
            release.set()
            await invocation
            with self.assertRaises(asyncio.CancelledError):
                await closing
            await rpc.close(timeout=None)
            await self.commands.close(timeout=None)
            self.assertEqual(self.active(), [])
            self.assertTrue(rpc._closing.done())
        finally:
            release.set()
            await asyncio.gather(invocation, *(() if closing is None else (closing,)), return_exceptions=True)

    async def test_cancelled_reservation_joins_and_removes_only_unsubmitted_pending_rpc(self):
        entered, release = threading.Event(), threading.Event()
        rpc = self.hub._work_rpc
        reserve = rpc._completion.reserve
        def held(**kwargs):
            entered.set()
            if not release.wait(4):
                raise TimeoutError('Original reservation was not released')
            return reserve(**kwargs)
        async def invoke():
            request = {'verb': 'work_add', 'args': self.args, 'operationId': 'cancelled-reservation',
                'token': 'operator-secret'}
            proof = await self.hub.authenticate_caller(request, object(), True)
            context = self.hub._authenticated_caller_context.set(proof)
            try:
                await rpc.execute(proof, 'work_add', self.args, 'operator')
            finally:
                rpc.abort()
                self.hub._authenticated_caller_context.reset(context)
        original = None
        try:
            with patch.object(rpc._completion, 'reserve', side_effect=held):
                original = asyncio.create_task(invoke())
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                original.cancel()
                await asyncio.sleep(.02)
                self.assertFalse(original.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await original
            self.assertEqual(self.submitted, [])
            self.assertEqual(self.store.q(
                "SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:pending:%'"), [])
            self.assertEqual(self.active(), [])
            await rpc.close(timeout=None)
            await self.commands.close(timeout=None)
        finally:
            release.set()
            if original is not None:
                await asyncio.gather(original, return_exceptions=True)

    async def test_actual_cli_retries_a_discarded_hub_response_with_the_same_id(self):
        connections, mutations, dropped = set(), [], False
        async def receive(reader, writer):
            nonlocal dropped
            task = asyncio.current_task()
            connections.add(task)
            try:
                raw = await reader.readline()
                request = json.loads(raw)
                lose = request['verb'] == 'work_add' and not dropped
                if request['verb'] == 'work_add':
                    mutations.append({key: value for key, value in request.items() if key != 'token'})
                if lose:
                    dropped = True
                retained_reader = SimpleNamespace(readline=AsyncMock(return_value=raw), at_eof=reader.at_eof)
                retained_writer = SimpleNamespace(write=(lambda value: None) if lose else writer.write,
                    drain=writer.drain, close=writer.close, is_closing=writer.is_closing,
                    get_extra_info=writer.get_extra_info)
                await self.hub.handle_conn(retained_reader, retained_writer, tcp=True)
                await writer.wait_closed()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(receive, '127.0.0.1', 0)
        address = server.sockets[0].getsockname()
        def connect(timeout):
            return socket.create_connection(address, timeout=timeout), True
        try:
            with patch.object(cli, 'connect', side_effect=connect), \
                    patch.object(cli, 'tcp_token', return_value='operator-secret'), \
                    patch.object(cli, 'validate_callback', return_value=False):
                response = await asyncio.to_thread(cli.call, 'work_add', self.args)
            self.assertTrue(response['ok'], response)
            self.assertTrue(dropped)
            self.assertEqual(len(mutations), 2)
            self.assertEqual(mutations[0], mutations[1])
            self.assertEqual(mutations[0]['operationId'], response['operationId'])
            self.assertEqual(len(self.mutations()), 1)
            self.assertEqual(len(self.store.outbox_pending()), 1)
            self.assertEqual(self.active(), [])
        finally:
            server.close()
            await server.wait_closed()
            if connections:
                await asyncio.gather(*tuple(connections))
