"""Offline KV tests; these do not qualify broker behavior."""
import unittest
from types import SimpleNamespace
from agentmux_contracts import ContractError, canonical_bytes
from nats.js.errors import KeyNotFoundError, KeyWrongLastSequenceError
from state_owner.views import OwnerView
from state_owner.test_ledger import record, SCOPE


class KV:
    def __init__(self):
        self.entry = None
        self.race = False

    async def get(self, key):
        if self.entry is None:
            raise KeyNotFoundError()
        return self.entry

    async def create(self, key, value):
        if self.entry:
            raise KeyWrongLastSequenceError()
        self.entry = SimpleNamespace(value=value, revision=1)

    async def update(self, key, value, last):
        if self.race:
            self.race = False
            raise KeyWrongLastSequenceError()
        if self.entry.revision != last:
            raise KeyWrongLastSequenceError()
        self.entry = SimpleNamespace(value=value, revision=last + 1)


class ViewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.kv = KV()
        self.scope = SCOPE
        self.view = OwnerView(self.kv, owner_hub_id='hub-one', owner_domain='task', scope=self.scope)

    def record(self, seq, state=None):
        value = record('operation-' + str(seq), seq, seq - 1)
        if state is not None:
            value['state'] = state
        return SimpleNamespace(sequence=seq, record=canonical_bytes(value))

    async def test_newer_wins_and_replay_matches(self):
        self.assertTrue(await self.view.apply(self.record(2)))
        self.assertFalse(await self.view.apply(self.record(1)))
        self.assertFalse(await self.view.apply(self.record(2)))
        with self.assertRaisesRegex(ContractError, 'owner_view_conflict'):
            await self.view.apply(self.record(2, {'changed': True}))
        with self.assertRaisesRegex(ContractError, 'owner_view_stale'):
            await self.view.read('task-one', expected=self.record(1))

    async def test_cas_retry_and_corruption(self):
        await self.view.apply(self.record(1))
        self.kv.race = True
        await self.view.apply(self.record(2))
        self.assertEqual((await self.view.read('task-one', expected=self.record(2)))['sourceRevision'], 2)
        self.kv.entry.value = b'{"private":"secret"}'
        with self.assertRaisesRegex(ContractError, '^owner_view_corrupt$'):
            await self.view.apply(self.record(3))

    async def test_rebuild_requires_source_and_never_dispatches(self):
        with self.assertRaisesRegex(ContractError, 'owner_view_source_empty'):
            await self.view.rebuild(SimpleNamespace(latest=None))
        self.assertTrue(await self.view.rebuild(SimpleNamespace(latest=self.record(3))))
        self.assertNotIn('org', repr(self.view))

    async def test_same_revision_tampering_and_incomplete_record_fail(self):
        from agentmux_contracts import strict_loads
        await self.view.apply(self.record(1))
        value = strict_loads(self.kv.entry.value)
        value['record']['state']['status'] = 'tampered'
        self.kv.entry.value = canonical_bytes(value)
        with self.assertRaisesRegex(ContractError, 'owner_view_stale'):
            await self.view.read('task-one', expected=self.record(1))
        del value['record']['operation']
        self.kv.entry.value = canonical_bytes(value)
        with self.assertRaisesRegex(ContractError, 'owner_view_corrupt'):
            await self.view.read('task-one', expected=self.record(1))
        with self.assertRaisesRegex(ContractError, 'owner_view_corrupt'):
            await self.view.apply(self.record(2, {'large': 'a' * 65536}))

    def test_bad_configuration(self):
        for timeout in (0, -1, float('nan'), float('inf'), True, 31):
            with self.assertRaisesRegex(ContractError, 'owner_view_configuration'):
                OwnerView(self.kv, owner_hub_id='hub', owner_domain='task',
                          scope=SCOPE, timeout=timeout)
        with self.assertRaisesRegex(ContractError, 'owner_view_configuration'):
            OwnerView(self.kv, owner_hub_id='hub.*', owner_domain='task', scope=SCOPE)
