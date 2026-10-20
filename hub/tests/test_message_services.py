"""Offline checks for Messages' restricted service boundary and stored outcomes."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from hub.fed import envelope, guard, ledger
from hub.fed.message_services import build_message_context
from hub.fed.plugins.messages import Messages
from hub.fed.runtime import Federation
from hub.store import HubError, Store
from hub.tests.test_fed_unit import policy


class MessageServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / "hub.db"))
        self.events = []

        async def db(fn, *args, **kwargs):
            return fn(*args, **kwargs)

        async def event(kind, data):
            self.events.append((kind, data))

        self.owner = SimpleNamespace(me="nick", node="mac", fcfg={"primary": True},
                                     policy=policy(), presence={}, store=self.store, db=db,
                                     local_event=event, kick=lambda: None)
        for name in ("sender_of", "resolve_repo", "address_of", "stage", "publish"):
            setattr(self.owner, name, getattr(Federation, name).__get__(self.owner))
        self.ctx = build_message_context(self.owner)
        self.plugin = Messages()

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def incoming(self, target=None):
        return envelope.make("message", "alice", "other", None, "nick",
                             {"body": "hello", "sender": {"operator": True}, "target": target})

    def decision(self):
        return SimpleNamespace(local_repo="falcon", trust="auto", untrusted=False)

    async def test_qualified_send_keeps_original_reply_and_events_after_success_only(self):
        result = {'id': 'original-queued-id', 'to': 'peer:alice', 'kind': 'handoff', 'queued': True}
        commands = SimpleNamespace(send=AsyncMock(return_value=result))
        ctx = replace(self.ctx, commands=commands)
        with patch('hub.fed.plugins.messages.envelope.make', side_effect=AssertionError('must use owner result')):
            self.assertIs(await self.plugin.send(ctx, 'operator', 'peer:alice', 'handoff', 'body'), result)
        commands.send.assert_awaited_once_with('operator', 'peer:alice', 'handoff', 'body', None, None, None)
        self.assertEqual([e[0] for e in self.events], ['handoff_sent'])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        self.events.clear()
        commands.send.side_effect = HubError('unconfirmed')
        with self.assertRaises(HubError):
            await self.plugin.send(ctx, 'operator', 'peer:alice', 'handoff', 'body')
        self.assertEqual(self.events, [])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_qualified_delivery_refusal_cannot_fall_back_to_direct_store(self):
        commands = SimpleNamespace(receive=AsyncMock(return_value='to_operator'))
        ctx, incoming, decision = replace(self.ctx, commands=commands), self.incoming(), self.decision()
        self.assertEqual(await self.plugin.on_envelope(ctx, incoming, decision), 'to_operator')
        commands.receive.assert_awaited_once_with(incoming, decision)
        commands.receive.side_effect = HubError('unconfirmed')
        with self.assertRaises(HubError):
            await self.plugin.on_envelope(ctx, incoming, decision)
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])

    async def test_qualified_context_requires_the_exact_enrolled_client(self):
        from agentmux_contracts import ContractError
        self.owner._qualified_messages = True
        for client in (None, SimpleNamespace(bind=lambda f: None, check=lambda f: None)):
            self.owner._message_commands = client
            with self.assertRaises(ContractError):
                build_message_context(self.owner)

    async def test_context_is_frozen_and_has_no_raw_runtime_handles(self):
        for name in ("hub", "store", "db", "js", "nc", "policy", "fcfg", "publish"):
            self.assertFalse(hasattr(self.ctx, name), name)
        with self.assertRaises(FrozenInstanceError):
            self.ctx.me = "other"
        with self.assertRaises(FrozenInstanceError):
            self.ctx.settings.primary = False
        self.owner.fcfg["primary"] = False
        self.assertTrue(self.ctx.settings.primary)
        self.assertFalse(build_message_context(self.owner).settings.primary)

    async def test_duplicate_delivery_uses_existing_store_key(self):
        env = self.incoming()
        for _ in range(2):
            self.assertEqual(await self.plugin.on_envelope(self.ctx, env, self.decision()), "delivered")
        rows = self.store.q("SELECT * FROM messages")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["idem_key"], f"fed:{env['id']}")
        self.assertEqual(rows[0]["target"], "virtual:operator")
        self.assertIn("peer:alice", rows[0]["body"])

    async def test_missing_role_falls_back_with_same_duplicate_key(self):
        env = self.incoming({"role": "worker"})
        self.assertEqual(await self.plugin.on_envelope(self.ctx, env, self.decision()), "to_operator")
        await self.plugin.on_envelope(self.ctx, env, self.decision())
        rows = self.store.q("SELECT * FROM messages")
        self.assertEqual(len(rows), 1)
        self.assertIn("for role:falcon/worker", rows[0]["body"])

    async def test_secondary_node_declines_operator_and_missing_agent(self):
        self.owner.fcfg["primary"] = False
        ctx = build_message_context(self.owner)
        for target in (None, {"role": "worker", "agent": "missing"}):
            self.assertEqual(await self.plugin.on_envelope(ctx, self.incoming(target), self.decision()),
                             "not_hosted")
        self.assertEqual(self.store.q("SELECT * FROM messages"), [])

    async def test_handoff_stages_outbox_and_notifies_after_success(self):
        result = await self.plugin.send(self.ctx, "operator", "peer:alice", "handoff", "hello", "ref", "code")
        self.assertTrue(result["queued"])
        self.assertEqual(self.events[0][0], "handoff_sent")
        self.assertEqual(self.events[0][1]["code"], "code")
        self.assertEqual(len(ledger.outbox_pending(self.store)), 1)

    async def test_existing_context_publish_rechecks_changed_policy(self):
        self.owner.policy = policy(repos={"falcon": {"peers": ["bob"]}})
        with self.assertRaises(guard.Refused):
            await self.plugin.send(self.ctx, "operator", "peer:alice/falcon/worker", "handoff", "hello")
        self.assertEqual(self.events, [])
        self.assertEqual(ledger.outbox_pending(self.store), [])

    async def test_publisher_rejects_other_domains_and_routes(self):
        for kind, sender, target, route in (
                ("knowledge", "nick", "*", "am.know.nick.r000000000000"),
                ("message", "alice", "nick", "am.msg.alice.nick"),
                ("message", "nick", "alice", "am.msg.nick.bob")):
            env = envelope.make(kind, sender, "mac", None, target, {"body": "hello"})
            with self.assertRaises(HubError):
                await self.ctx.publisher.publish(env, route, None, target)
        self.assertEqual(ledger.outbox_pending(self.store), [])

    async def test_primary_change_after_context_creation_blocks_operator_effect(self):
        self.owner.fcfg["primary"] = False
        self.assertEqual(await self.plugin.on_envelope(self.ctx, self.incoming(), self.decision()),
                         "not_hosted")
        self.assertEqual(self.store.q("SELECT * FROM messages"), [])

    async def test_publisher_cannot_omit_repository_scope(self):
        env = envelope.make("message", "nick", "mac", self.owner.policy.rid_of("falcon"),
                            "alice", {"body": "hello"})
        with self.assertRaises(HubError):
            await self.ctx.publisher.publish(env, "am.msg.nick.alice", None, "alice")
        self.assertEqual(ledger.outbox_pending(self.store), [])

    async def test_peer_denied_while_delivery_waits_does_not_reach_fallback(self):
        async def queued_db(fn, *args, **kwargs):
            self.owner.policy = policy(peers={"alice": {"trust": "deny"}})
            return fn(*args, **kwargs)

        self.owner.db = queued_db
        self.assertEqual(await self.plugin.on_envelope(self.ctx, self.incoming(), self.decision()), "denied")
        self.assertEqual(self.store.q("SELECT * FROM messages"), [])

    async def test_repository_withdrawn_while_delivery_waits_is_not_posted(self):
        env = self.incoming({"role": "worker"})
        env["rid"] = self.owner.policy.rid_of("falcon")

        async def queued_db(fn, *args, **kwargs):
            self.owner.policy = policy(repos={})
            return fn(*args, **kwargs)

        self.owner.db = queued_db
        self.assertEqual(await self.plugin.on_envelope(self.ctx, env, self.decision()), "not_shared")
        self.assertEqual(self.store.q("SELECT * FROM messages"), [])

    async def test_approved_message_preserves_runtime_decision(self):
        self.owner.policy = policy(peers={"alice": {"trust": "approve"}})
        decision = guard.Decision("deliver", trust="approve", untrusted=True, approved=True)
        self.assertEqual(await self.plugin.on_envelope(self.ctx, self.incoming(), decision), "delivered")
        self.assertIn("REMOTE DATA", self.store.q1("SELECT body FROM messages")["body"])

    async def test_secondary_node_preserves_missing_role_operator_fallback(self):
        self.owner.fcfg["primary"] = False
        env = self.incoming({"role": "worker"})
        env["rid"] = self.owner.policy.rid_of("falcon")
        self.assertEqual(await self.plugin.on_envelope(build_message_context(self.owner), env, self.decision()),
                         "to_operator")
        self.assertEqual(self.store.q1("SELECT target FROM messages")["target"], "virtual:operator")

    async def test_denial_between_role_failure_and_fallback_blocks_fallback(self):
        attempts = 0

        async def queued_db(fn, *args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                self.owner.policy = policy(peers={"alice": {"trust": "deny"}})
            return fn(*args, **kwargs)

        self.owner.db = queued_db
        self.assertEqual(await self.plugin.on_envelope(self.ctx, self.incoming({"role": "worker"}),
                                                      self.decision()), "denied")
        self.assertEqual(self.store.q("SELECT * FROM messages"), [])
