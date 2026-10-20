"""Actual Hub caller/proof and owner admission, with controlled application transport."""
import asyncio
import copy
import hashlib
import json
from contextvars import ContextVar
from types import SimpleNamespace
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.fed import ledger
from hub.fed.message_bridge import MessageBridgeIntents
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.messages import Messages
from hub.fed.runtime import Federation
from hub.server import Hub, AuthenticatedLocalCaller
from hub.store import HubError
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .legacy_messages_client import LegacyMessageCommandClient
from . import test_message_bridge_owner as owner_support


class LegacyMessageClientTests(owner_support.BridgeOwnerFixture, unittest.IsolatedAsyncioTestCase):
    application_key = owner_support.MessageBridgeServiceTests.application_key

    async def asyncSetUp(self):
        await owner_support.MessageBridgeServiceTests.asyncSetUp(self)
        patch('capability_owner.legacy_messages_client.datetime', _Clock).start()
        patch('hub.fed.message_bridge.datetime', _Clock).start()
        self.hub = object.__new__(Hub)
        self.hub.store, self.hub.db = self.store, self.owner.db
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('message-client-proof', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.presence, self.fed.session = {}, self.owner.session
        self.fed.stats = dict.fromkeys(('received', 'duplicates', 'dropped', 'quarantined', 'delivered', 'errors'), 0)
        self.fed.log = Mock()
        self.fed._qualified_messages = True
        self.fed.nc = SimpleNamespace(_subs={})
        self.hub.fed = self.fed
        self.drop_reply = False
        self.submitted = []
        human = self.application_key()
        material = strict_loads(human._material)
        material['callerRef'] = ref('service')
        material['messageCommands'].update(authenticatedCaller='federation',
            transportRef=ref('legacy-service-transport'), grantRefs=self.legacy_grants['service'])
        self.sessions = tuple(self.session_for(key) for key in (human, ApplicationClientKey(material)))
        self.client = LegacyMessageCommandClient(self.hub, self.sessions)
        self.client.bind(self.fed)
        self.fed._message_commands = self.client
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.client)
        adapter = TrustedPluginAdapter(Messages(), builtin_context_factory('messages'))
        self.fed.plugin_adapters, self.fed.routes = {'messages': adapter}, {'message': adapter, 'handoff': adapter}
        self.fed.plugins = {'messages': adapter.original}
        self.fed.verbs, self.fed.plugin_verbs = self.fed._core_verbs(), {}
        self.addAsyncCleanup(self.client.close, timeout=None)

    def session_for(self, key):
        loop = asyncio.get_running_loop()
        session = object.__new__(ApplicationClientSession)
        enrollment = {k: key.selection[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'messageCommands')}
        session.message_enrollment = lambda: strict_loads(canonical_bytes(enrollment))
        def submit(*, contract_id, operation_id, payload, expires_at, deadline):
            selected = key.selection['messageCommands']
            claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
                'profileId': 'profile-one', 'authorityId': 'authority-one',
                'transportRef': selected['transportRef'], 'grantRef': selected['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.message_transport_000001'}
            raw = key.sign_command(claims, subject=selected['subject'], now=NOW)
            response = asyncio.run_coroutine_threadsafe(self.endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=max(.1, deadline-time.monotonic()))
            self.submitted.append(strict_loads(raw)['claims'])
            if self.drop_reply and contract_id == 'federation-message-send':
                self.drop_reply = False
                raise TimeoutError()
            return key.verify_command_response(response, raw, subject=selected['subject'], now=NOW)
        session.message_command = submit
        return session

    async def post(self, *, body='original', attribution=None, kind='note'):
        request = {'token': 'operator-secret', 'verb': 'post',
            'args': {'to': 'peer:alice/falcon/worker', 'kind': kind, 'body': body}}
        if attribution is not None:
            request['as'] = attribution
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=True)
        return json.loads(writer.write.call_args.args[0])

    async def restart_client(self):
        await self.client.close(timeout=None)
        self.client = LegacyMessageCommandClient(self.hub, self.sessions)
        self.client.bind(self.fed)
        self.fed._message_commands = self.client
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.client)
        self.addAsyncCleanup(self.client.close, timeout=None)

    def incoming_message(self, env):
        from nats.aio.msg import Msg
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = subscription
        self.fed.session.own_subscription(subscription)
        self.addAsyncCleanup(self.fed.session.close)
        return Msg(_client=self.fed.nc, subject='am.msg.alice.nick', data=canonical_bytes(env), _sid=1)

    async def approve(self, qid):
        request = {'token': 'operator-secret', 'verb': 'fed_approve', 'args': {'id': qid}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=True)
        return json.loads(writer.write.call_args.args[0])

    async def concurrent_write(self, contract):
        other = await self.bridge_prepare('send', operation='concurrent-writer')
        original, advanced = self.resource.legacy, False
        async def interleave(authority, raw):
            nonlocal advanced
            if strict_loads(raw)['contractId'] == contract and not advanced:
                advanced = True
                await original(authority, other)
            return await original(authority, raw)
        return patch.object(self.resource, 'legacy', side_effect=interleave)

    async def test_actual_hub_send_preserves_original_id_outbox_and_authenticated_actor(self):
        result = await self.post(attribution='forged-display')
        self.assertTrue(result['ok'], result)
        row = self.store.q1('SELECT * FROM fed_outbox')
        self.assertEqual(row['msg_id'], result['result']['id'])
        send = next(c for c in self.submitted if c['contractId'] == 'federation-message-send')
        self.assertEqual(send['transportRef'], ref('transport'))
        self.assertEqual(send['payload']['attribution'], 'operator')
        self.assertEqual(strict_loads(row['payload'])['data']['sender'], {'operator': True})
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_confirmed_handoff_source_is_exact_current_task_and_single_use(self):
        result = await self.post(kind='handoff')
        self.assertTrue(result['ok'], result)
        async def other_task():
            return self.client.take_publication_source()
        with self.assertRaises(ContractError):
            await asyncio.create_task(other_task())
        source = self.client.take_publication_source()
        self.assertEqual(source['id'], result['result']['id'])
        stored = self.resource._journal.outcome(source['operationId'], source['payloadDigest'])
        self.assertEqual(stored['reply']['resourceRef'], source['resourceRef'])
        self.assertEqual(stored['envelope']['payload']['input']['requestedTo'], 'peer:alice/falcon/worker')
        with self.assertRaises(ContractError):
            self.client.take_publication_source()
        self.assertTrue((await self.post())['ok'])
        with self.assertRaises(ContractError):
            self.client.take_publication_source()

    async def test_disconnected_peer_transport_preserves_local_queue_and_held_approval(self):
        from hub.tests.test_fed_unit import policy
        self.fed.session = self.fed.nc = None
        self.assertTrue((await self.post())['ok'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.fed.policy = self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.value()['envelope']
        qid = ledger.quarantine_add(self.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        self.assertTrue((await self.approve(qid))['ok'])
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)

    async def test_lost_reply_and_new_client_recover_original_intent_without_second_publication(self):
        self.drop_reply = True
        first = await self.post()
        self.assertFalse(first['ok'])
        original = self.store.q1('SELECT * FROM fed_outbox')
        pending = self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")
        self.assertEqual(len(pending), 1)
        await self.client.close(timeout=None)
        self.client = LegacyMessageCommandClient(self.hub, self.sessions)
        self.client.bind(self.fed)
        self.fed._message_commands = self.client
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.client)
        self.addAsyncCleanup(self.client.close, timeout=None)
        recovered = await self.post()
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result']['id'], original['msg_id'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-message-send']), 1)
        self.assertTrue(any(c['contractId'] == 'federation-message-outcome' for c in self.submitted))
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_actual_receive_uses_service_actor_and_original_delivery_then_seen(self):
        from nats.aio.msg import Msg
        env = self.value()['envelope']
        subject = 'am.msg.alice.nick'
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = subscription
        self.fed.session.own_subscription(subscription)
        self.addAsyncCleanup(self.fed.session.close)
        msg = Msg(_client=self.fed.nc, subject=subject, data=canonical_bytes(env), _sid=1)
        with patch('hub.fed.runtime._ack', AsyncMock()):
            self.assertEqual(await self.fed.receive(subject, msg.data, msg), 'delivered')
            self.assertEqual(await self.fed.receive(subject, msg.data, msg), 'duplicate')
        delivered = next(c for c in self.submitted if c['contractId'] == 'federation-message-deliver')
        self.assertEqual(delivered['transportRef'], ref('legacy-service-transport'))
        self.assertEqual(delivered['payload']['attribution'], 'federation')
        self.assertEqual(self.store.q1('SELECT * FROM messages')['idem_key'], 'fed:' + env['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM deliveries')), 1)
        self.assertTrue(ledger.seen(self.store, env['id']))

    async def test_actual_fed_approve_delivers_before_held_state_changes(self):
        from hub.tests.test_fed_unit import policy
        self.fed.policy = self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.value()['envelope']
        qid = ledger.quarantine_add(self.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        original_post = self.resource._post
        def post_while_held(*args, **kwargs):
            self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
            return original_post(*args, **kwargs)
        request = {'token': 'operator-secret', 'verb': 'fed_approve', 'args': {'id': qid}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        with patch.object(self.resource, '_post', side_effect=post_while_held):
            await self.hub.handle_conn(reader, writer, tcp=True)
        reply = json.loads(writer.write.call_args.args[0])
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['result']['outcome'], 'delivered')
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertIn('REMOTE DATA', self.store.q1('SELECT body FROM messages')['body'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)

    async def test_forged_reused_stale_proofs_and_changed_call_arguments_refuse(self):
        request = {'token': 'operator-secret', 'verb': 'post',
            'args': {'to': 'peer:alice/falcon/worker', 'body': 'original'}}
        writer = SimpleNamespace()
        proof = await self.hub.authenticate_caller(request, writer, True)
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            with self.assertRaises(ContractError):
                await self.client.send('operator', request['args']['to'], 'note', 'substituted')
            with self.assertRaises(HubError):
                await self.client.send('operator', request['args']['to'], 'note', 'original')
        finally:
            self.hub._authenticated_caller_context.reset(token)
        for forged in (object.__new__(AuthenticatedLocalCaller),
                await self.hub.authenticate_caller(request, writer, True)):
            token = self.hub._authenticated_caller_context.set(forged)
            try:
                with patch('hub.server.time.monotonic', return_value=10**20):
                    with self.assertRaises(HubError):
                        await self.client.send('operator', request['args']['to'], 'note', 'original')
            finally:
                self.hub._authenticated_caller_context.reset(token)
        self.assertEqual(self.submitted, [])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_changed_protected_reply_binding_cannot_replace_a_pending_send(self):
        self.drop_reply = True
        self.assertFalse((await self.post())['ok'])
        original = self.store.q1('SELECT * FROM fed_outbox')
        await self.client.close(timeout=None)
        selected = self.sessions[0].message_enrollment()
        selected['messageCommands']['serviceInstanceId'] = 'replacement-owner'
        self.sessions[0].message_enrollment = lambda: strict_loads(canonical_bytes(selected))
        self.client = LegacyMessageCommandClient(self.hub, self.sessions)
        self.client.bind(self.fed)
        self.fed._message_commands = self.client
        self.addAsyncCleanup(self.client.close, timeout=None)
        before = len(self.submitted)
        self.assertFalse((await self.post())['ok'])
        self.assertEqual(len(self.submitted), before)
        self.assertEqual(self.store.q1('SELECT * FROM fed_outbox')['msg_id'], original['msg_id'])
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")), 1)

    async def test_cancelled_hub_call_retains_original_worker_and_pending_intent_until_joined(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.owner.db
        async def delayed(function, *args, **kwargs):
            if function == self.resource._journal.commit:
                entered.set()
                await release.wait()
            return await original(function, *args, **kwargs)
        self.owner.db = delayed
        task = asyncio.create_task(self.post())
        try:
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with self.assertRaisesRegex(ContractError, 'legacy_message_cleanup_incomplete'):
                await self.client.close(timeout=.01)
            self.assertFalse(task.done())
            self.assertTrue(self.client._workers)
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await self.client.close(timeout=None)
        self.assertFalse(self.client._workers)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")), 1)

    async def test_delivery_conflict_retains_terminal_attempt_and_redelivery_uses_a_fresh_attempt(self):
        env = self.value()['envelope']
        msg = self.incoming_message(env)
        patcher = await self.concurrent_write('federation-message-deliver')
        with patcher, patch('hub.fed.runtime._ack', AsyncMock()), patch('nats.aio.msg.Msg.nak', AsyncMock()):
            self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'error')
            self.assertFalse(ledger.seen(self.store, env['id']))
            self.assertEqual(self.store.q('SELECT * FROM messages'), [])
            self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'delivered')
        attempts = [c for c in self.submitted if c['contractId'] == 'federation-message-deliver']
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0]['operationId'], attempts[1]['operationId'])
        self.assertEqual(attempts[0]['payload']['input'], attempts[1]['payload']['input'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertTrue(ledger.seen(self.store, env['id']))
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_approval_conflict_can_retry_the_same_held_item_with_a_fresh_attempt(self):
        from hub.tests.test_fed_unit import policy
        self.fed.policy = self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.value()['envelope']
        qid = ledger.quarantine_add(self.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        patcher = await self.concurrent_write('federation-message-approve')
        with patcher:
            self.assertFalse((await self.approve(qid))['ok'])
            self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
            self.assertTrue((await self.approve(qid))['ok'])
        attempts = [c for c in self.submitted if c['contractId'] == 'federation-message-approve']
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0]['operationId'], attempts[1]['operationId'])
        self.assertEqual(attempts[0]['payload']['input'], attempts[1]['payload']['input'])
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)

    async def test_restart_after_delivery_commit_before_seen_recovers_the_original_attempt(self):
        env = self.value()['envelope']
        msg = self.incoming_message(env)
        original_db = self.fed.db
        async def before_seen(function, *args, **kwargs):
            if function.__name__ == 'done':
                raise RuntimeError('stopped before seen')
            return await original_db(function, *args, **kwargs)
        with patch.object(self.fed, 'db', side_effect=before_seen):
            with self.assertRaises(RuntimeError):
                await self.fed.receive(msg.subject, msg.data, msg)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertFalse(ledger.seen(self.store, env['id']))
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")), 1)
        await self.restart_client()
        with patch('hub.fed.runtime._ack', AsyncMock()):
            self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'delivered')
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-message-deliver']), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertTrue(ledger.seen(self.store, env['id']))
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_restart_after_approved_delivery_before_transition_recovers_original_attempt(self):
        from hub.tests.test_fed_unit import policy
        self.fed.policy = self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.value()['envelope']
        qid = ledger.quarantine_add(self.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        original_db = self.hub.db
        async def before_transition(function, *args, **kwargs):
            if function == ledger.quarantine_decide:
                raise HubError('stopped before transition')
            return await original_db(function, *args, **kwargs)
        with patch.object(self.hub, 'db', side_effect=before_transition):
            self.assertFalse((await self.approve(qid))['ok'])
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        await self.restart_client()
        self.assertTrue((await self.approve(qid))['ok'])
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-message-approve']), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_restart_after_seen_before_recovery_cleanup_retires_on_duplicate(self):
        env = self.value()['envelope']
        msg = self.incoming_message(env)
        with patch.object(self.client, 'confirm_receive', AsyncMock(side_effect=HubError('stopped after seen'))):
            with self.assertRaises(HubError):
                await self.fed.receive(msg.subject, msg.data, msg)
        self.assertTrue(ledger.seen(self.store, env['id']))
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")), 1)
        await self.restart_client()
        with patch('hub.fed.runtime._ack', AsyncMock()):
            self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'duplicate')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_confirmed_approval_recovery_cleanup_survives_restart(self):
        from hub.tests.test_fed_unit import policy
        self.fed.policy = self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.value()['envelope']
        qid = ledger.quarantine_add(self.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        with patch.object(self.client, 'confirm_receive', AsyncMock(side_effect=HubError('stopped after approval'))):
            self.assertFalse((await self.approve(qid))['ok'])
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'")), 1)
        await self.restart_client()
        self.assertTrue((await self.post())['ok'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def code_share(self, *, push=None, after_handoff=None):
        from hub.fed.plugins.code import Code
        from hub.fed.code_services import GitOperations, RepositoryDirectory
        for statement in Code.tables:
            self.store.db.execute(statement)
        self.fed.loop = self.fed.wake = None
        code = TrustedPluginAdapter(Code(), builtin_context_factory('code'))
        self.fed.plugin_adapters['code'] = code
        self.fed.plugins['code'] = code.original
        self.fed.verbs['fed_code_share'] = code.verbs()['share']
        self.fed.plugin_verbs['fed_code_share'] = (code, 'share')
        request = {'token': 'operator-secret', 'verb': 'fed_code_share',
            'args': {'repo': 'falcon', 'note': 'please review', 'to': 'peer:alice/falcon/worker'}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        self.code_reader, self.code_writer = reader, writer
        original_dispatch = Hub.dispatch.__get__(self.hub)
        async def dispatch(verb, args, caller):
            result = await original_dispatch(verb, args, caller)
            if after_handoff is not None:
                await after_handoff(result, caller)
            return result
        async def controlled_push(*_args):
            if push is not None:
                await push()
        checkout = SimpleNamespace(repo='falcon', rid=self.resource.repository_id, remote='origin',
            url='git@github.com:Adag/Falcon.git', path='/not-used')
        with patch.object(RepositoryDirectory, 'checkout', AsyncMock(return_value=checkout)), \
                patch.object(GitOperations, 'revision', AsyncMock(return_value='a' * 40)), \
                patch.object(GitOperations, 'branch', AsyncMock(return_value='feature')), \
                patch.object(GitOperations, 'push', AsyncMock(side_effect=controlled_push)), \
                patch.object(self.hub, 'dispatch', side_effect=dispatch), \
                patch.object(GitOperations, 'summary', AsyncMock(return_value=(None, ['one.py'], 'one.py | 1 +', 'log'))):
            await self.hub.handle_conn(reader, writer, tcp=True)
        self.assertFalse(self.hub._code_share_invocations)
        self.assertFalse(self.hub._authenticated_callers)
        return json.loads(writer.write.call_args.args[0])

    async def test_actual_code_share_keeps_its_derived_handoff_through_the_message_owner(self):
        response = await self.code_share()
        self.assertTrue(response['ok'], response)
        result = response['result']
        share = self.store.q1('SELECT * FROM p_code_shares WHERE id=?', (result['id'],))
        self.assertEqual(share['sha'], 'a' * 40)
        handoff = strict_loads(self.store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?',
            (result['handoff']['id'],))['payload'])
        self.assertEqual(handoff['type'], 'handoff')
        self.assertEqual(handoff['data']['code'], result['id'])
        self.assertEqual(handoff['data']['body'], 'please review\none.py | 1 +')
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_code_share_outlasting_initial_proof_reauthenticates_the_same_live_request(self):
        async def slow_git():
            await asyncio.sleep(5.05)
            with self.assertRaises(HubError):
                self.hub.current_authenticated_caller()
        response = await self.code_share(push=slow_git)
        self.assertTrue(response['ok'], response)
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-message-send']), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)

    async def test_code_share_token_revocation_closed_connection_and_changed_request_refuse(self):
        async def revoked():
            self.hub.operator_sha = hashlib.sha256(b'rotated-operator-token').hexdigest()
        self.assertFalse((await self.code_share(push=revoked))['ok'])
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        async def closed():
            self.code_writer.is_closing = lambda: True
        self.assertFalse((await self.code_share(push=closed))['ok'])
        async def changed():
            key = self.hub._code_share_invocation_context.get()
            self.hub._code_share_invocations[key].dispatched_request['args']['to'] = 'peer:bob/falcon/worker'
        self.assertFalse((await self.code_share(push=changed))['ok'])
        self.assertEqual(self.submitted, [])
        self.assertTrue(all(strict_loads(r['payload'])['type'] == 'code' for r in self.store.q('SELECT payload FROM fed_outbox')))

    async def test_code_share_changed_principal_refuses_and_original_invocation_is_single_use(self):
        async def changed_principal():
            self.hub.operator_sha = hashlib.sha256(b'rotated-operator-token').hexdigest()
            self.store.repo_add('falcon')
            session = self.store.register('falcon', 'worker', 'one', 'codex', {})
            self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
                (hashlib.sha256(b'operator-secret').hexdigest(), session))
        self.assertFalse((await self.code_share(push=changed_principal))['ok'])
        self.assertEqual(self.submitted, [])
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        async def reuse(result, caller):
            with self.assertRaises(HubError):
                await self.client.send(caller, 'peer:alice/falcon/worker', 'handoff',
                    'please review\none.py | 1 +', code=result['id'])
        self.assertTrue((await self.code_share(after_handoff=reuse))['ok'])
        self.assertEqual(len([c for c in self.submitted if c['contractId'] == 'federation-message-send']), 1)

    async def test_code_share_cancellation_disposes_private_connection_and_proofs(self):
        entered, wait = asyncio.Event(), asyncio.Event()
        captured = []
        async def stalled():
            key = self.hub._code_share_invocation_context.get()
            captured.append(self.hub._code_share_invocations[key])
            entered.set()
            await wait.wait()
        task = asyncio.create_task(self.code_share(push=stalled))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.hub._code_share_invocations)
        self.assertFalse(self.hub._authenticated_callers)
        self.assertEqual(captured[0].request, b'')
        self.assertIsNone(captured[0].reader)
        self.assertIsNone(captured[0].writer)
        self.assertFalse(captured[0].proofs)
        self.assertNotIn('operator-secret', repr(captured[0]))

    async def test_direct_code_plugin_call_without_original_dispatch_cannot_refresh_authority(self):
        request = {'token': 'operator-secret', 'verb': 'fed_code_share',
            'args': {'repo': 'falcon', 'to': 'peer:alice/falcon/worker', 'note': 'please review'}}
        proof = await self.hub.authenticate_caller(request, SimpleNamespace(), True)
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            with self.assertRaises(HubError):
                await self.hub.reauthenticate_code_share_caller()
            with self.assertRaises(ContractError):
                await self.client.send('operator', request['args']['to'], 'handoff', 'please review', code='untrusted')
        finally:
            self.hub._authenticated_caller_context.reset(token)
        self.assertEqual(self.submitted, [])

    async def test_code_handoff_cannot_use_a_missing_remote_or_substituted_source(self):
        from hub.fed import envelope
        from hub.fed.plugins.code import Code
        from hub.fed.code_services import CodeShareOwner
        for statement in Code.tables:
            self.store.db.execute(statement)
        self.fed.loop = self.fed.wake = None
        env = envelope.make('code', 'nick', 'mac', self.resource.repository_id, '*',
            {'ref': 'refs/agentmux/nick/feature_aaaaaaaa', 'sha': 'a' * 40, 'base': None,
                'files': ['one.py'], 'stat': 'one.py | 1 +', 'log': 'log', 'note': 'please review',
                'slug': 'feature_aaaaaaaa', 'author': 'operator', 'remote': 'github.com/adag/falcon'})
        await CodeShareOwner(self.fed).publish(env, 'falcon')
        async def dispatch(verb, args, caller):
            return await self.client.send(caller, args['to'], 'handoff', args.get('derivedBody', 'please review\none.py | 1 +'),
                code=args.get('shareId', env['id']))
        self.hub.dispatch = dispatch
        async def attempt(**changes):
            request = {'token': 'operator-secret', 'verb': 'fed_code_share', 'args': {
                'repo': 'falcon', 'note': 'please review', 'to': 'peer:alice/falcon/worker', **changes}}
            reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
            writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
            await self.hub.handle_conn(reader, writer, tcp=True)
            return json.loads(writer.write.call_args.args[0])
        self.assertFalse((await attempt(shareId='missing'))['ok'])
        self.assertFalse((await attempt(derivedBody='substituted body'))['ok'])
        self.store.db.execute("UPDATE p_code_shares SET from_peer='alice' WHERE id=?", (env['id'],))
        self.assertFalse((await attempt())['ok'])
        self.assertEqual(self.submitted, [])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
