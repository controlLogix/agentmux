"""Actual authenticated Hub reads over the retained signed work owner."""
import asyncio
from contextvars import ContextVar
from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from agentmux_contracts import canonical_bytes, strict_loads
from hub.fed.runtime import Federation
from hub.server import CallerClassificationUnavailable
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from identity.test_authority import NOW
from identity.test_service import _Clock
from . import test_local_work_client as support
from .test_work_bridge_owner import WorkBridgeFixture


class LocalWorkHubReadTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    open_client = support.LocalWorkClientTests.open_client
    session_for = support.LocalWorkClientTests.session_for
    agent = support.LocalWorkClientTests.agent

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.local_work_client', 'hub.server'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.caller = 'operator'
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('local-work-read-proof', default=None)
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
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed._qualified_work = self.hub, True
        self.fed.verbs, self.fed.plugin_verbs = self.fed._core_verbs(), {}
        self.hub.fed = self.fed

    def install_client(self):
        self.hub._work_storage_commands = self.commands
        self.hub._local_work_commands = self.client

    async def packet(self, verb, arguments, *, token='operator-secret'):
        request = {'verb': verb, 'args': arguments, 'token': token}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()),
            at_eof=lambda: False)
        responses = []
        writer = SimpleNamespace(write=Mock(side_effect=lambda raw: responses.append(json.loads(raw))),
            drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=True)
        writer.close.assert_called_once()
        self.assertEqual(len(responses), 1)
        return responses[0]

    def target(self, *, repo='falcon', name='target', maximum=2):
        return reg(self.store, repo, 'worker', name,
            snap={'capabilities': ['python'], 'max_active': maximum})

    def remote(self, target, *, repo='falcon', title='Scoped remote', privileged=False):
        row = self.store.work_create('operator', repo, 'agent:' + target, title)
        self.store.claim(target, work_id=row['id'])
        self.store.db.execute('UPDATE work_items SET origin_peer=?, fed_flags=? WHERE id=?',
            ('alice', json.dumps({'privileged_ok': privileged}), row['id']))
        return row

    def assert_refused_without_work(self, response, *rows):
        self.assertFalse(response['ok'], response)
        public = canonical_bytes(response).decode()
        for row in rows:
            self.assertNotIn(row['id'], public)
            self.assertNotIn(row['title'], public)

    async def test_operator_inbox_peek_has_only_signed_scoped_work_and_does_not_ack_mail(self):
        target = self.target(maximum=3)
        ready = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Scoped ready')
        active = self.remote(target)
        hidden = self.remote(target, repo='other', title='Hidden other repository')
        message = self.store.post('virtual:operator', 'agent:' + target, 'note', 'Mail remains unreceived')
        original_state = self.store.q1('SELECT state FROM deliveries WHERE message_id=?',
            (message['id'],))['state']
        response = await self.packet('inbox', {'session': target, 'ack': True})
        self.assertTrue(response['ok'], response)
        value = response['result']
        self.assertEqual(value['session'], target)
        self.assertEqual(value['acked'], [])
        self.assertEqual([row['id'] for row in value['claimable']], [ready['id']])
        self.assertEqual([row['id'] for row in value['active']], [active['id']])
        self.assertEqual(value['messages'][0]['id'], message['id'])
        self.assertEqual(self.store.q1('SELECT state FROM deliveries WHERE message_id=?',
            (message['id'],))['state'], original_state)
        self.assertNotIn(hidden['id'], canonical_bytes(response).decode())
        self.assertNotIn(hidden['title'], canonical_bytes(response).decode())
        self.assertEqual(self.submitted[-1]['payload']['input']['query'],
            {'kind': 'readiness', 'session': target})
        self.assertNotIn(asyncio.current_task(), self.commands._disclosures)

    async def test_direct_caller_and_forged_proof_cannot_read_work(self):
        target = self.target()
        arguments = {'session': target}
        with self.assertRaises(HubError):
            await self.hub.dispatch('inbox', arguments, 'operator')
        class ForgedProof:
            pass
        token = self.hub._authenticated_caller_context.set(ForgedProof())
        try:
            with self.assertRaises(HubError):
                await self.hub.dispatch('inbox', arguments, 'operator')
        finally:
            self.hub._authenticated_caller_context.reset(token)
        self.assertEqual(self.submitted, [])

    async def test_missing_qualified_proof_never_falls_back_to_operator_work_reads(self):
        target = self.target()
        with patch.object(self.hub, 'authenticate_caller',
                side_effect=CallerClassificationUnavailable('controlled unavailable classification')):
            with patch.object(self.hub, 'caller_of', new=AsyncMock(return_value='operator')):
                response = await self.packet('inbox', {'session': target})
        self.assert_refused_without_work(response)
        self.assertEqual(self.submitted, [])

    async def test_actual_agent_reads_itself_and_cannot_choose_another_inbox_target(self):
        await self.agent(maximum=2)
        self.install_client()
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        other = self.target(name='other')
        own = self.store.work_create('operator', 'falcon', 'agent:' + self.caller, 'Own ready work')
        foreign = self.store.work_create('operator', 'falcon', 'agent:' + other, 'Other agent work')
        response = await self.packet('inbox', {'session': other}, token='agent-secret')
        self.assertTrue(response['ok'], response)
        self.assertEqual(response['result']['session'], self.caller)
        self.assertEqual([row['id'] for row in response['result']['claimable']], [own['id']])
        self.assertNotIn(foreign['id'], canonical_bytes(response).decode())
        self.assertEqual(self.submitted[-1]['payload']['input']['query']['session'], self.caller)

    async def test_invalid_actual_token_cannot_borrow_the_operator_enrollment(self):
        target = self.target()
        response = await self.packet('inbox', {'session': target}, token='forged-operator')
        self.assert_refused_without_work(response)
        self.assertEqual(self.submitted, [])

    async def test_target_generation_changed_during_final_authentication_is_not_disclosed(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'agent:' + target, 'Sensitive original target')
        original, calls = self.hub._caller_identity, 0
        async def changed(*args, **kwargs):
            nonlocal calls
            result = await original(*args, **kwargs)
            calls += 1
            if calls == 2:
                self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target,))
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=changed):
            response = await self.packet('inbox', {'session': target})
        self.assertEqual(calls, 2)
        self.assert_refused_without_work(response, row)

    async def test_current_caller_changed_after_final_target_await_is_not_disclosed(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'agent:' + target, 'Sensitive original caller')
        original, calls = self.hub._check_work_targets, 0
        async def changed():
            nonlocal calls
            await original()
            calls += 1
            if calls == 2:
                self.hub.operator_sha = hashlib.sha256(b'replaced-operator-secret').hexdigest()
        with patch.object(self.hub, '_check_work_targets', side_effect=changed):
            response = await self.packet('inbox', {'session': target})
        self.assertGreaterEqual(calls, 2)
        self.assert_refused_without_work(response, row)

    async def test_original_owner_expiry_before_reply_never_writes_sensitive_work(self):
        target = self.target()
        row = self.store.work_create('operator', 'falcon', 'agent:' + target, 'Sensitive expired result')
        state = strict_loads(self.js.messages[-1].data)
        next(grant for grant in state['state']['grants'] if
            grant['ref'] == self.work_grants['human']['federation-work-read'])['expiresAt'] = (
                NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(state)
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        original, calls = self.hub._caller_identity, 0
        async def expired(*args, **kwargs):
            nonlocal calls
            result = await original(*args, **kwargs)
            calls += 1
            if calls == 2:
                timer = patch('capability_owner.legacy_work_client.datetime', Later)
                timer.start()
                self.addCleanup(timer.stop)
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=expired):
            response = await self.packet('inbox', {'session': target})
        self.assert_refused_without_work(response, row)

    async def test_qualified_gate_uses_scoped_active_work_and_operator_default(self):
        target = self.target(maximum=3)
        allowed = self.remote(target, privileged=True)
        hidden = self.remote(target, repo='other', title='Hidden denied privilege', privileged=False)
        response = await self.packet('fed_gate', {'session': target})
        self.assertTrue(response['ok'], response)
        self.assertEqual(response['result'], {'session': target,
            'remote_work': [{'id': allowed['id'], 'title': allowed['title'], 'peer': 'alice',
                'privileged_ok': True}], 'privileged_allowed': True})
        self.assertNotIn(hidden['id'], canonical_bytes(response).decode())
        self.assertNotIn(hidden['title'], canonical_bytes(response).decode())
        self.store.db.execute('UPDATE work_items SET fed_flags=? WHERE id=?',
            (json.dumps({'privileged_ok': False}), allowed['id']))
        denied = await self.packet('fed_gate', {'session': target})
        self.assertTrue(denied['ok'], denied)
        self.assertFalse(denied['result']['privileged_allowed'])
        self.assertEqual([row['id'] for row in denied['result']['remote_work']], [allowed['id']])
        default = await self.packet('fed_gate', {})
        self.assertTrue(default['ok'], default)
        self.assertEqual(default['result'], {'session': 'operator', 'remote_work': [],
            'privileged_allowed': True})

    async def test_qualified_show_and_list_use_only_authorized_owner_rows(self):
        target = self.target()
        parent = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Scoped parent')
        self.store.claim(target, work_id=parent['id'])
        child = self.store.work_create('agent:' + target, 'falcon', 'role:falcon/worker',
            'Scoped child', parent_id=parent['id'])
        hidden = self.store.work_create('operator', 'other', 'role:other/worker', 'Hidden other work')
        listed = await self.packet('work_list', {})
        self.assertTrue(listed['ok'], listed)
        self.assertEqual({row['id'] for row in listed['result']}, {parent['id'], child['id']})
        shown = await self.packet('work_show', {'work_id': parent['id']})
        self.assertTrue(shown['ok'], shown)
        self.assertEqual(shown['result'], self.store.work(parent['id']))
        self.assertNotIn(hidden['id'], canonical_bytes(listed).decode())
        denied = await self.packet('work_show', {'work_id': hidden['id']})
        self.assertTrue(denied['ok'], denied)
        self.assertIsNone(denied['result'])
        foreign = await self.packet('work_list', {'repo': 'other'})
        self.assert_refused_without_work(foreign, hidden)

    async def test_qualified_status_counts_only_authorized_work(self):
        visible = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Visible work')
        self.store.work_create('operator', 'other', 'role:other/worker', 'Hidden work')
        original = self.store.status
        def checked_status(*args, **kwargs):
            if kwargs.get('include_work') is not False:
                raise AssertionError('qualified status counted raw work')
            return original(*args, **kwargs)
        with patch.object(self.store, 'status', side_effect=checked_status):
            response = await self.packet('status', {})
        self.assertTrue(response['ok'], response)
        self.assertEqual(response['result']['work'], {visible['state']: 1})
