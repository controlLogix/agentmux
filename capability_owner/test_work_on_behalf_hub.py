"""Operator attribution through real Unix connections and signed work owners."""
import asyncio
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.tests.test_hub_offline import reg
from hub.fed import ledger
from hub.fed.work_services import offer_digest
from identity.test_authority import ref
from identity.test_service import _Clock
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_local_work_client as local_support
from . import test_work_on_behalf as operator_support
from .work_rpc import WorkRpc
from .local_work_client import LocalWorkClient
from . import test_work_runtime as runtime_support


class OperatorWorkHubTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    open_client = local_support.LocalWorkClientTests.open_client
    agent = local_support.LocalWorkClientTests.agent

    def session_for(self, identity, repository, endpoint):
        if self.caller == 'operator':
            self.assertEqual((identity, repository, endpoint), ('human', 'falcon', self.endpoint))
            return operator_support.OperatorWorkClientTests.session_for(self)
        return local_support.LocalWorkClientTests.session_for(self, identity, repository, endpoint)

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
        self.hub._authenticated_caller_context = ContextVar('operator-work-native-proof', default=None)
        self.hub.tp = SimpleNamespace(socket='amux668-test')
        self.panes = ''
        # Kernel peer credentials remain real. Control only the process/pane
        # inventory so this test does not depend on the user's terminal layout.
        parent = patch('hub.server.parent_pid', return_value=1)
        parent.start()
        self.addCleanup(parent.stop)
        panes = patch('hub.server.subprocess.run', side_effect=lambda *a, **kw:
            SimpleNamespace(returncode=0, stdout=self.panes))
        panes.start()
        self.addCleanup(panes.stop)
        original_db = self.hub.db
        async def checked_db(function, *args, **kwargs):
            if function in (self.store.work_create, self.store.claim, self.store.heartbeat,
                    self.store.release, self.store.cancel, self.store.claim_path, self.store.work):
                raise AssertionError('Hub bypassed the signed work owner')
            if function in (self.store.q, self.store.q1) and args and 'work_items' in args[0].lower():
                raise AssertionError('Hub queried raw work SQL')
            return await original_db(function, *args, **kwargs)
        self.hub.db = checked_db
        await self.open_client()
        self.install_client()
        self.hub.fed = SimpleNamespace(enabled=False, local_event=AsyncMock())
        self.hub._notify_work_owner = AsyncMock()
        self.connections = set()
        self.socket_path = str(Path(self.directory.name) / 'on-behalf.sock')
        self.server = await asyncio.start_unix_server(self.receive, path=self.socket_path)
        self.addAsyncCleanup(self.close_server)

    def install_client(self):
        self.hub._work_storage_commands, self.hub._local_work_commands = self.commands, self.client
        self.hub._work_rpc = WorkRpc(self.hub, self.commands, self.client)

    async def receive(self, reader, writer):
        task = asyncio.current_task()
        self.connections.add(task)
        try:
            await self.hub.handle_conn(reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    async def close_server(self):
        self.server.close()
        await self.server.wait_closed()
        if self.connections:
            await asyncio.gather(*tuple(self.connections))

    async def packet(self, verb, args, *, operation_id, target=None, tcp=False, token='operator-secret'):
        request = {'verb': verb, 'args': args, 'operationId': operation_id}
        if target is not None:
            request['as'] = target
        if tcp:
            request['token'] = token
            # The token path uses the same actual handler and signed owner.
            raw = json.dumps(request).encode() + b'\n'
            replies = []
            writer = SimpleNamespace(write=lambda value: replies.append(json.loads(value)),
                drain=AsyncMock(), close=lambda: None, is_closing=lambda: False)
            reader = SimpleNamespace(readline=AsyncMock(return_value=raw), at_eof=lambda: False)
            original = asyncio.create_task(self.hub.handle_conn(reader, writer, tcp=True))
            await original
            self.assertEqual(len(replies), 1)
            return replies[0]
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(json.dumps(request).encode() + b'\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), 8)
            self.assertTrue(response, 'Hub closed without a response')
            return json.loads(response)
        finally:
            writer.close()
            await writer.wait_closed()
            if self.connections:
                await asyncio.gather(*tuple(self.connections))

    def target(self, *, repo='falcon', name='target', maximum=3):
        return reg(self.store, repo, 'worker', name,
            snap={'capabilities': ['python'], 'max_active': maximum})

    def mutations(self, action):
        return [x for x in self.submitted if x['contractId'] == 'federation-work-' + action]

    def assert_operator_target(self, action, target):
        request = self.mutations(action)[-1]
        self.assertEqual(request['payload']['attribution'], 'operator')
        self.assertEqual(request['payload']['input']['onBehalfOf'],
            {'session': target, 'generation': self.store.agent(target)['generation']})
        self.assertEqual(request['transportRef'], ref('transport'))
        self.assertEqual(request['grantRef'], self.work_grants['human']['federation-work-' + action])

    async def test_unix_operator_as_create_claim_heartbeat_path_release_keep_actual_authority(self):
        target = self.target()
        created = await self.packet('work_add', {'to': 'role:*/worker', 'title': 'Operator agent work'},
            target=target, operation_id='operator-create')
        self.assertTrue(created['ok'], created)
        row = created['result']
        self.assertEqual((row['created_by'], row['repo']), ('agent:' + target, 'falcon'))
        claimed = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='operator-claim')
        self.assertTrue(claimed['ok'], claimed)
        self.assertEqual(claimed['result']['claimed']['claimed_by'], target)
        heartbeat = await self.packet('heartbeat', {}, target=target, operation_id='operator-heartbeat')
        self.assertTrue(heartbeat['ok'], heartbeat)
        self.assertEqual(heartbeat['result'], {'renewed': 1})
        path = await self.packet('claim_path', {'path': 'src/original.py', 'work_id': row['id']},
            target=target, operation_id='operator-path')
        self.assertTrue(path['ok'], path)
        self.assertEqual(path['result']['holder'], target)
        released = await self.packet('release', {'work_id': row['id'], 'outcome': 'done', 'result': 'Exact raw result'},
            target=target, operation_id='operator-release')
        self.assertTrue(released['ok'], released)
        self.assertEqual(released['result'], self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
        self.assertNotIn('children', released['result'])
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])
        for action in ('create', 'claim', 'heartbeat', 'claim-path', 'release'):
            self.assert_operator_target(action, target)
        self.hub._notify_work_owner.assert_awaited_once_with(released['result'], target)
        self.hub.fed.local_event.assert_awaited_once_with('work_released', released['result'], require_completion=True)

    async def test_registered_and_unregistered_panes_cannot_override_even_themselves(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Ready')
        self.store.db.execute('UPDATE agents SET pane_pid=? WHERE session=?', (os.getpid(), target))
        registered = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='pane-self')
        self.assertFalse(registered['ok'], registered)
        self.assertIn('--as is only for the operator', registered['error'])
        self.store.db.execute('UPDATE agents SET pane_pid=NULL WHERE session=?', (target,))
        self.panes = str(os.getpid())
        unregistered = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='pane-unregistered')
        self.assertFalse(unregistered['ok'], unregistered)
        self.assertIn('--as is only for the operator', unregistered['error'])
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')
        self.assertEqual(self.submitted, [])

    async def test_tcp_operator_override_is_ignored(self):
        target = self.target()
        created = await self.packet('work_add', {'to': 'role:falcon/worker', 'title': 'TCP operator'},
            target=target, tcp=True, operation_id='tcp-create')
        self.assertTrue(created['ok'], created)
        self.assertEqual(created['caller'], 'operator')
        self.assertEqual(created['result']['created_by'], 'virtual:operator')
        self.assertNotIn('onBehalfOf', self.mutations('create')[-1]['payload']['input'])
        refused = await self.packet('claim', {'work_id': created['result']['id']},
            target=target, tcp=True, operation_id='tcp-operator-claim')
        self.assertFalse(refused['ok'], refused)

    async def test_tcp_agent_token_remains_self_only_despite_operator_attribution_request(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'TCP agent work')
        await self.agent(maximum=2)
        self.install_client()
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        claimed = await self.packet('claim', {'work_id': row['id']},
            target=target, tcp=True, token='agent-secret', operation_id='tcp-agent-claim')
        self.assertTrue(claimed['ok'], claimed)
        self.assertEqual(claimed['caller'], self.caller)
        self.assertEqual(claimed['result']['claimed']['claimed_by'], self.caller)
        self.assertNotIn('onBehalfOf', self.mutations('claim')[-1]['payload']['input'])

    async def test_global_capacity_and_repository_scope_apply_to_operator_target(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        target = self.target(repo='other', maximum=1)
        hidden = self.store.work_create('operator', 'other', 'role:other/worker', 'Hidden global capacity')
        self.store.claim(target, work_id=hidden['id'], repository='other')
        ready = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Allowed group work')
        limited = await self.packet('claim', {}, target=target, operation_id='capacity')
        self.assertTrue(limited['ok'], limited)
        self.assertIsNone(limited['result']['claimed'])
        self.assertNotIn(hidden['id'], canonical_bytes(limited).decode())
        self.store.release(target, hidden['id'], 'done')
        claimed = await self.packet('claim', {}, target=target, operation_id='available')
        self.assertTrue(claimed['ok'], claimed)
        self.assertEqual(claimed['result']['claimed']['id'], ready['id'])
        denied = await self.packet('claim_path', {'path': 'private.py', 'repo': 'other'},
            target=target, operation_id='foreign-path')
        self.assertFalse(denied['ok'], denied)
        foreign = await self.packet('claim', {'work_id': hidden['id']}, target=target, operation_id='foreign-work')
        self.assertFalse(foreign['ok'], foreign)
        self.assertNotIn(hidden['id'], canonical_bytes(foreign).decode())

    async def test_target_replacement_after_original_selection_refuses_before_effect(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Ready')
        original = self.hub._work_on_behalf
        async def replaced(admitted):
            selected = await original(admitted)
            self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target,))
            return selected
        with patch.object(self.hub, '_work_on_behalf', side_effect=replaced):
            refused = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='stale-target')
        self.assertFalse(refused['ok'], refused)
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_final_target_replacement_refuses_disclosure(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Sensitive original')
        original, count = self.hub._caller_identity, 0
        async def replaced(*args, **kwargs):
            nonlocal count
            result = await original(*args, **kwargs)
            count += 1
            if count == 2:
                self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target,))
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=replaced):
            refused = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='final-target')
        self.assertFalse(refused['ok'], refused)
        self.assertNotIn(row['id'], canonical_bytes(refused).decode())
        self.assertEqual(self.store.work(row['id'])['claimed_by'], target)

    async def test_lost_target_claim_reply_recovers_original_without_agent_impersonation(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original uncertain claim')
        self.drop_after = 'federation-work-claim'
        failed = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='lost-target-claim')
        self.assertFalse(failed['ok'], failed)
        recovered = await self.packet('claim', {'work_id': row['id']}, target=target, operation_id='lost-target-claim')
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result']['claimed']['claimed_by'], target)
        self.assertEqual(len(self.mutations('claim')), 1)
        self.assert_operator_target('claim', target)

    async def test_operator_as_cannot_escalate_to_cancel(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Keep ready')
        response = await self.packet('work_cancel', {'work_id': row['id']},
            target=target, operation_id='no-cancel-escalation')
        self.assertFalse(response['ok'], response)
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')
        self.assertEqual(self.mutations('cancel'), [])

    async def test_unix_operator_as_federated_offer_keeps_agent_sender_and_original_replay(self):
        await self.hub._work_rpc.close(timeout=None)
        await self.commands.close(timeout=None)
        with patch.object(self, 'session_for',
                side_effect=lambda identity: runtime_support.WorkRuntimeTests.session_for(self, identity)):
            await runtime_support.WorkRuntimeTests.setup_runtime(self)
        self.fed.cfg['federation'].update(enabled=True, url='nats://127.0.0.1:4222')
        self.commands = self.storage
        self.client = LocalWorkClient(self.hub, self.commands)
        self.install_client()
        target = self.target()
        for verb, arguments in (('fed_work_add', {'to': 'role:falcon/worker', 'title': 'Agent offer'}),
                ('work_add', {'to': 'role:falcon/worker', 'title': 'Agent local offer', 'federate': True})):
            with self.subTest(verb=verb):
                original = await self.packet(verb, arguments, target=target, operation_id='operator-' + verb)
                self.assertTrue(original['ok'], original)
                self.assertEqual(original['caller'], target)
                self.assertEqual(original['result']['created_by'], 'agent:' + target)
                replay = await self.packet(verb, arguments, target=target, operation_id='operator-' + verb)
                self.assertEqual(replay, original)
                self.assert_operator_target('offer', target)
                row = self.store.q1('SELECT * FROM work_items WHERE id=?', (original['result']['id'],))
                flags = strict_loads(row['fed_flags'])
                item = next(strict_loads(record['payload']) for record in ledger.outbox_pending(self.store)
                    if strict_loads(record['payload'])['id'] == flags['env'])
                self.assertEqual(item['data']['sender'],
                    {'rid': self.resource.repository_id, 'role': 'worker', 'agent': 'target'})
                self.assertEqual(flags['offer_digest'], offer_digest(item))
        self.assertEqual(len(self.mutations('offer')), 2)
        self.assertEqual(len(ledger.outbox_pending(self.store)), 2)
