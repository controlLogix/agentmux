"""Real receive/apply and Hub authentication boundaries with controlled transport."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from contextvars import ContextVar
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from nats.aio.msg import Msg
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from capability_owner.legacy_messages_client import LegacyMessageCommandClient
from hub.fed import envelope, guard, ledger
from hub.fed.message_bridge import MessageBridgeIntents, MessageIntent
from hub.fed.runtime import Federation, _v_approve
from hub.fed.session import FederationSession
from hub.server import Hub
from hub.store import Store
from hub.tests.test_fed_unit import policy


class MessageBridgeIntentsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.hub = object.__new__(Hub)
        self.hub.store = Store(str(Path(self.directory.name) / 'hub.db'))
        self.addCleanup(self.hub.store.db.close)
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('message-test-caller', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        async def db(function, *args, **kwargs):
            return function(*args, **kwargs)
        self.hub.db = db
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.policy = policy()
        self.fed.cfg = self.fed.policy.cfg
        self.fed.stats = dict.fromkeys(('received', 'duplicates', 'dropped', 'quarantined', 'delivered', 'errors'), 0)
        self.fed.log = Mock()
        self.fed._qualified_messages = True
        self.fed.session = FederationSession()
        self.addAsyncCleanup(self.fed.session.close)
        self.fed.nc = SimpleNamespace(_subs={})
        self.client = object.__new__(LegacyMessageCommandClient)
        self.client._hub = self.hub
        self.client._federation = self.fed
        self.fed._message_commands = self.client
        self.addCleanup(patch.stopall)
        patch.object(LegacyMessageCommandClient, 'check', return_value=None).start()
        patch.object(LegacyMessageCommandClient, 'intent_binding',
            side_effect=lambda command, env: {'command': command, 'peer': 'alice', 'channel': 'one'}).start()
        self.intents = MessageBridgeIntents(self.fed, self.client)
        self.fed._message_intents = self.intents
        self.retained = []
        async def receive(fed, env, decision):
            self.retained.append(strict_loads(self.intents.consume(env, decision).content))
            with self.assertRaises(ContractError):
                self.intents.consume(env, decision)
            return 'delivered'
        self.fed.routes = {'message': SimpleNamespace(name='messages', on_envelope=receive)}

    def incoming(self):
        return envelope.make('message', 'alice', 'other', None, 'nick',
            {'body': 'original', 'sender': {'operator': True}, 'target': None})

    def message(self, env):
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = subscription
        self.fed.session.own_subscription(subscription)
        return Msg(_client=self.fed.nc, subject='am.msg.alice.nick', data=canonical_bytes(env), _sid=1)

    async def test_actual_receive_owns_one_original_intent_and_marks_seen_after_delivery(self):
        env = self.incoming()
        msg = self.message(env)
        with patch('hub.fed.runtime._ack', AsyncMock()):
            self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'delivered')
        self.assertEqual(self.retained[0]['envelope'], env)
        self.assertEqual(self.retained[0]['command'], 'deliver')
        self.assertTrue(ledger.seen(self.hub.store, env['id']))
        self.assertFalse(self.intents._pending)

    async def test_direct_construction_unowned_subscription_changed_content_and_expiry_refuse(self):
        with self.assertRaises(TypeError):
            MessageIntent()
        env = self.incoming()
        msg = self.message(env)
        decision = guard.inbound(self.fed.policy, msg.subject, env)
        self.fed.session._resources.clear()
        with self.assertRaises(ContractError):
            self.intents.inbound(msg.subject, env, decision, msg)
        self.message(env)
        changed = copy.deepcopy(env)
        changed['data']['body'] = 'substituted'
        with self.assertRaises(ContractError):
            self.intents.inbound(msg.subject, changed, decision, msg)
        with self.intents.inbound(msg.subject, env, decision, msg):
            with patch('hub.fed.message_bridge.time.monotonic', return_value=10**20):
                with self.assertRaises(ContractError):
                    self.intents.consume(env, decision)

    async def test_actual_authenticated_approve_mints_intent_before_transition(self):
        self.fed.policy = policy(peers={'alice': {'trust': 'approve'}})
        env = self.incoming()
        qid = ledger.quarantine_add(self.hub.store, env, 'am.msg.alice.nick', 'msg', 'alice', 'approve')
        request = {'token': 'operator-secret', 'verb': 'fed_approve', 'args': {'id': qid, 'privileged': False}}
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock())
        async def dispatch(verb, args, caller):
            self.assertEqual(ledger.quarantine_get(self.hub.store, qid)['state'], 'held')
            return await _v_approve(self.fed, args, caller)
        self.hub.dispatch = dispatch
        await self.hub.handle_conn(reader, writer, tcp=True)
        self.assertTrue(json.loads(writer.write.call_args.args[0])['ok'])
        self.assertEqual(self.retained[0]['quarantineId'], qid)
        self.assertEqual(self.retained[0]['approver'], 'operator')
        self.assertEqual(ledger.quarantine_get(self.hub.store, qid)['state'], 'approved')
        self.assertFalse(self.intents._pending)
