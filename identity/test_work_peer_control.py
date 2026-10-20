"""Work control routes retain exact selected source and peer possession proof."""
import base64
import copy
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner.knowledge_host import KnowledgeStoreHost
from capability_owner.test_knowledge_host import SelectedKnowledgeCompositionFixture
from capability_owner.work_host import WorkStoreHost
from hub.fed import envelope
from hub.fed.peer_control import PeerControlIngress
from .authority import AuthoritySnapshot
from .peer_control import check_authority, control_claims, control_storage
from .test_authority import ref
from .test_peer_control import PeerControlFixture


class WorkPeerControlFixture(PeerControlFixture):
    def setUp(self):
        super().setUp()
        work = self.value['storage'].pop('knowledge')
        work['channels'][0]['resourceRef'] = ref('work-one')
        self.value['storage']['work'] = work
        route = self.value['peerControl']['routes'][0]
        route.update(routeId='work-alice', resourceRef=ref('work-one'))
        self.selection = self.selected()
        record = strict_loads(self.snapshot.record)
        next(g for g in record['state']['grants'] if g['ref'] == ref('control-grant'))['resourceId'] = 'work-one'
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)

    async def asyncSetUp(self):
        await SelectedKnowledgeCompositionFixture.asyncSetUp(self)
        selected = self.value['storage']['work']
        self.source = WorkStoreHost(selected['source'], repository=selected['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()


class WorkPeerControlTests(WorkPeerControlFixture, unittest.IsolatedAsyncioTestCase):
    def test_work_resource_resolves_without_knowledge_or_caller_domain(self):
        route = self.value['peerControl']['routes'][0]
        name, declaration = control_storage(self.selection.policy, route)
        self.assertEqual(name, 'work')
        self.assertEqual(declaration, self.value['storage']['work'])
        self.assertNotIn('knowledge', self.selection.policy['storage'])
        for change in ('unselected', 'foreign', 'duplicate', 'unsupported'):
            value = copy.deepcopy(self.value)
            if change == 'unselected':
                route = {**route, 'resourceRef': ref('unselected-work')}
            elif change == 'foreign':
                route = {**self.value['peerControl']['routes'][0], 'resourceRef':
                    {**ref('work-one'), 'ownerHubId': 'foreign'}}
            elif change == 'duplicate':
                route = self.value['peerControl']['routes'][0]
                value['storage']['knowledge'] = copy.deepcopy(value['storage']['work'])
            else:
                route = self.value['peerControl']['routes'][0]
                value['storage']['arbitrary'] = value['storage'].pop('work')
            with self.subTest(change=change), self.assertRaises(ContractError):
                control_storage(value, route)

    def test_work_control_route_refuses_repository_peer_node_and_scope_changes(self):
        original = copy.deepcopy(self.value)
        for change in ('repository', 'peer', 'node', 'scope'):
            self.value = copy.deepcopy(original)
            route = self.value['peerControl']['routes'][0]
            if change == 'repository':
                route['repository']['localName'] = 'different'
            elif change == 'peer':
                route['localPeer'] = 'different'
            elif change == 'node':
                route['localNode'] = 'different'
            else:
                route['scope']['projectId'] = 'different'
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.selected()
        self.value = original

    async def test_work_ingress_accepts_supported_borrowed_source_and_refuses_lookalike(self):
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='work-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        self.assertEqual(ingress._storage_domain, 'work')
        self.assertIs(ingress._store_owner, self.source)
        selected = self.value['storage']['work']
        await self.source.close()
        knowledge = KnowledgeStoreHost(selected['source'], repository=selected['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(knowledge.close)
        await knowledge.start()
        borrowed = PeerControlIngress(self.selection, self.identity, knowledge, AsyncMock(), route_id='work-alice')
        self.addAsyncCleanup(borrowed.close, timeout=None)
        self.assertIs(borrowed._store_owner, knowledge)
        await knowledge.db(WorkStoreHost.check_work_tables, knowledge._store)
        with self.assertRaises(ContractError):
            PeerControlIngress(self.selection, self.identity,
                SimpleNamespace(_pins=knowledge._pins, _repository=knowledge._repository, _peer=knowledge._peer),
                AsyncMock(), route_id='work-alice')
        wrong = copy.deepcopy(knowledge._pins)
        wrong['database']['path'] += '.other'
        with patch.object(knowledge, '_pins', wrong), self.assertRaises(ContractError):
            PeerControlIngress(self.selection, self.identity, knowledge, AsyncMock(), route_id='work-alice')

    def test_mixed_domain_routes_resolve_only_their_exact_channel(self):
        value = copy.deepcopy(self.value)
        knowledge = copy.deepcopy(value['storage']['work'])
        knowledge['channels'][0]['resourceRef'] = ref('knowledge-one')
        value['storage']['knowledge'] = knowledge
        route = value['peerControl']['routes'][0]
        self.assertEqual(control_storage(value, route)[0], 'work')
        knowledge_route = {**route, 'resourceRef': ref('knowledge-one')}
        self.assertEqual(control_storage(value, knowledge_route)[0], 'knowledge')
        knowledge['channels'].append(copy.deepcopy(knowledge['channels'][0]))
        with self.assertRaises(ContractError):
            control_storage(value, knowledge_route)

    async def test_work_retains_resource_bound_signature_and_current_authority(self):
        route = self.value['peerControl']['routes'][0]
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='work-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        item = envelope.make('revoke', 'alice', 'mac')
        key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
        try:
            signature = base64.b64encode(key.sign(canonical_bytes(control_claims(route, item, 'am.ctl.alice')))).decode()
        finally:
            key.wipe()
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)):
            await check_authority(self.selection, self.identity, route_id='work-alice')
            raw = await self.source.db(ingress._retain, item, signature, self.snapshot.sequence)
            with patch.object(ingress, 'check'):
                handle = await ingress.recover(item['id'], payload_digest(item))
                self.assertEqual(await ingress.consume(handle, peer='alice',
                    repository_id=route['repository']['repositoryId']), raw)
                with self.assertRaises(ContractError):
                    await ingress.consume(handle, peer='alice', repository_id=route['repository']['repositoryId'])
        retained = strict_loads(raw)
        self.assertEqual(retained['binding']['resourceRef'], ref('work-one'))
        altered = copy.deepcopy(retained)
        altered['binding']['resourceRef'] = ref('knowledge-one')
        with self.assertRaises(ContractError):
            ingress._proof(canonical_bytes(altered), item['id'], payload_digest(item))
        record = strict_loads(self.snapshot.record)
        next(g for g in record['state']['grants'] if g['ref'] == ref('control-grant'))['status'] = 'revoked'
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(record), self.snapshot.sequence + 1))), patch.object(ingress, 'check'), \
                self.assertRaises(ContractError):
            await ingress.recover(item['id'], payload_digest(item))

    async def test_ordinary_message_cannot_mint_work_control_admission(self):
        from nats.aio.msg import Msg
        ingress = PeerControlIngress(self.selection, self.identity, self.source, AsyncMock(), route_id='work-alice')
        self.addAsyncCleanup(ingress.close, timeout=None)
        item = envelope.make('revoke', 'alice', 'mac')
        message = Msg(_client=ingress._connection, subject='am.ctl.alice', data=canonical_bytes(item), _sid=1)
        with patch.object(ingress, 'check'), self.assertRaises(ContractError):
            ingress._message(message)
        self.assertEqual(await self.source.db(self.source._store.q,
            "SELECT * FROM fed_state WHERE k LIKE 'peer-control:%'"), [])
