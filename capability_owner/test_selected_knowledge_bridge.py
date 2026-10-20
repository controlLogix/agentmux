"""Selected knowledge bridge admission and shared source lifecycle."""
import copy
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .knowledge import KnowledgeStorageResource
from .knowledge_legacy import LegacyKnowledgeActor
from .messages import MessageStorageResource
from .selected_storage import SelectedStorageHost
from . import test_knowledge_host as support


class SelectedKnowledgeBridgeTests(unittest.IsolatedAsyncioTestCase):
    connection = support.SelectedKnowledgeCompositionTests.connection
    custody = support.SelectedKnowledgeCompositionTests.custody
    selected = support.SelectedKnowledgeCompositionTests.selected
    add_board = support.SelectedKnowledgeCompositionTests.add_board
    identity_inputs = support.SelectedKnowledgeCompositionTests.identity_inputs
    authority_record = support.SelectedKnowledgeCompositionTests.authority_record
    setUp = support.SelectedKnowledgeCompositionTests.setUp
    asyncSetUp = support.SelectedKnowledgeCompositionTests.asyncSetUp

    def actor(self):
        return {'identityRef': ref('human'), 'transportRef': ref('transport'), 'caller': 'operator',
            'grants': {'federation-knowledge-' + action: ref('knowledge-' + action)
                for action in ('share', 'approve', 'read', 'inspect', 'outcome')}}

    def configure(self, *, messages=False):
        selected = self.value['storage']['knowledge']
        selected['channels'][0]['legacyActors'] = [self.actor()]
        if messages:
            message = copy.deepcopy(selected)
            channel = message['channels'][0]
            channel.pop('legacyActors')
            channel.update(peer='alice', resourceRef=ref('messages-one'))
            self.value['storage']['messages'] = message
            selected['channels'][0]['messageSources'] = [ref('messages-one')]
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        next(t for t in state['transports'] if t['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        state['memberships'].append({'ref': ref('knowledge-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, reference in self.actor()['grants'].items():
            state['grants'].append({'ref': reference, 'callerRef': ref('human'), 'actorRef': ref('human'),
                'scope': copy.deepcopy(self.scope), 'contractId': contract, 'resourceId': 'knowledge-one',
                'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None,
                'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        return current

    async def check_authority(self, current):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current), self.snapshot.sequence))):
            await self.selection.check_storage_authority(self.identity)

    async def test_current_grants_membership_transport_and_human_approval_are_required(self):
        current = self.configure()
        await self.check_authority(current)
        def human(state):
            return next(i for i in state['identities'] if i['ref'] == ref('human'))
        def transport(state):
            return next(t for t in state['transports'] if t['ref'] == ref('transport'))
        changes = {
            'revoked grant': lambda s: s['grants'][-1].update(status='revoked'),
            'unknown grant': lambda s: s['grants'].pop(),
            'other resource': lambda s: s['grants'][-1].update(resourceId='other'),
            'other actor': lambda s: s['grants'][-1].update(actorRef=ref('plugin-one')),
            'other project': lambda s: s['grants'][-1]['scope'].update(projectId='other'),
            'hard denial': lambda s: s['grants'].append(dict(s['grants'][-1], ref=ref('deny-knowledge'), decision='denied')),
            'revoked membership': lambda s: s['memberships'][-1].update(status='revoked'),
            'revoked transport': lambda s: transport(s).update(status='revoked'),
            'revoked principal': lambda s: human(s).update(status='revoked'),
            'service operator': lambda s: human(s).update(kind='service'),
            'device approval': lambda s: human(s).update(kind='device'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(current)
                mutate(changed['state'])
                with self.assertRaises(ContractError):
                    await self.check_authority(changed)

    def test_selection_refuses_unknown_grants_and_wrong_caller_family(self):
        original = copy.deepcopy(self.value)
        changes = {
            'foreign grant': lambda a: a['grants']['federation-knowledge-share'].update(ownerHubId='other'),
            'unknown contract': lambda a: a['grants'].update({'federation-message-send': ref('wrong')}),
            'service share': lambda a: a.update(caller='federation'),
            'operator index': lambda a: a['grants'].update({'federation-knowledge-index': ref('index')}),
            'operator capture': lambda a: a['grants'].update({'federation-knowledge-capture': ref('capture')}),
            'operator withdraw': lambda a: a['grants'].update({'federation-knowledge-withdraw': ref('withdraw')}),
            'agent approval': lambda a: a.update(caller='falcon-worker-one'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                self.value = copy.deepcopy(original)
                actor = self.actor()
                mutate(actor)
                self.value['storage']['knowledge']['channels'][0]['legacyActors'] = [actor]
                with self.assertRaises(ContractError):
                    self.selected()

    def test_message_sources_require_exact_declared_binding(self):
        self.configure(messages=True)
        original = copy.deepcopy(self.value)
        changes = {
            'unknown source': lambda k,m: k['channels'][0]['messageSources'][0].update(id='other'),
            'foreign source': lambda k,m: k['channels'][0]['messageSources'][0].update(ownerHubId='other'),
            'different policy': lambda k,m: m['source']['policy'].update(sha256='sha256:' + '0'*64),
            'different peer': lambda k,m: m.update(localPeer='other'),
            'different node': lambda k,m: m.update(localNode='other'),
            'different repository': lambda k,m: m['repository'].update(localName='other'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                self.value = copy.deepcopy(original)
                mutate(self.value['storage']['knowledge'], self.value['storage']['messages'])
                with self.assertRaises(ContractError):
                    self.selected()

    async def test_selected_bridge_borrows_actual_message_owner_and_closes_before_store(self):
        await self.host.close(timeout=None)
        current = self.configure(messages=True)
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        self.clients[1].max_payload = 1048576
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current), self.snapshot.sequence))), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            bridge = self.host._receivers[0]._knowledge_bridge
            self.assertIsNotNone(bridge)
            self.assertIsNone(self.host._receivers[1]._knowledge_bridge)
            knowledge = next(r for r in self.host._resources if type(r) is KnowledgeStorageResource)
            messages = next(r for r in self.host._resources if type(r) is MessageStorageResource)
            self.assertTrue(all(type(a) is LegacyKnowledgeActor for a in knowledge._legacy_actors))
            self.assertEqual(knowledge._message_sources, (messages,))
            self.assertIs(knowledge._store, messages._store)
            self.assertEqual(len(self.host._message_stores), 1)
            source = self.host._message_stores[0]
            close = source.close
            async def checked_close(*args, **kwargs):
                self.assertTrue(bridge._closed)
                self.assertFalse(bridge._workers)
                await close(*args, **kwargs)
            with patch.object(source, 'close', checked_close):
                await self.host.close(timeout=None)
            self.assertIsNone(source._store)
        self.assertFalse(self.identity._closed)

    async def test_omitted_legacy_actors_does_not_enable_bridge(self):
        self.clients[1].max_payload = 1048576
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.assertTrue(all(r._knowledge_bridge is None for r in self.host._receivers))
            await self.host.close(timeout=None)

    async def test_message_source_future_revision_prevents_readiness(self):
        await self.host.close(timeout=None)
        current = self.configure(messages=True)
        self.value['storage']['knowledge']['channels'][0]['messageSources'][0]['revision'] = 2
        self.selection = self.selected()
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current), self.snapshot.sequence))), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            with self.assertRaises(ContractError):
                await self.host.start()
            self.assertFalse(self.host._ready)
            await self.host.close(timeout=None)
            self.assertEqual(self.host._receivers, [])
