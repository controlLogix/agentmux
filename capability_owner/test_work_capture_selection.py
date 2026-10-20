"""Selected capture uses only the declared Work owner on its original source."""
import copy
import threading
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .knowledge import KnowledgeStorageResource
from .test_knowledge_host import SelectedKnowledgeCompositionFixture
from .work import WorkStorageResource


class WorkCaptureSelectionTests(SelectedKnowledgeCompositionFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        knowledge = self.value['storage']['knowledge']
        work = copy.deepcopy(knowledge)
        work['channels'][0]['resourceRef'] = ref('work-one')
        self.value['storage']['work'] = work
        knowledge['channels'][0].update(workSources=[ref('work-one')], legacyActors=[{
            'identityRef': ref('human'), 'transportRef': ref('transport'), 'caller': 'operator',
            'grants': {'federation-knowledge-read': ref('knowledge-read')}}])
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        next(item for item in state['transports'] if item['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        state['memberships'].append({'ref': ref('capture-human-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        state['grants'].append({'ref': ref('knowledge-read'), 'callerRef': ref('human'),
            'actorRef': ref('human'), 'scope': copy.deepcopy(self.scope),
            'contractId': 'federation-knowledge-read', 'resourceId': 'knowledge-one',
            'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None,
            'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence)
        for client in self.clients:
            client.max_payload = 1048576

    async def start_host(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.host.check_health()

    async def test_start_binds_exact_work_owner_before_knowledge_on_one_source(self):
        await self.start_host()
        work = next(resource for resource in self.host._resources if type(resource) is WorkStorageResource)
        knowledge = next(resource for resource in self.host._resources if type(resource) is KnowledgeStorageResource)
        self.assertLess(self.host._resources.index(work), self.host._resources.index(knowledge))
        self.assertEqual(len(self.host._message_stores), 1)
        source = self.host._message_stores[0]
        self.assertIs(self.host._preconstructed_sources['work'], source)
        self.assertIs(self.host._preconstructed_sources['knowledge'], source)
        self.assertIs(work._source, source)
        self.assertIs(knowledge._owner._source, source)
        self.assertIs(work._store, knowledge._store)
        self.assertIs(work._store, source._store)
        self.assertIs(work._connection, source._store.db)
        self.assertIs(work._owner._executor, source._executor)
        self.assertIs(knowledge._owner._source._executor, source._executor)
        pins = knowledge._work_capture_sources
        self.assertEqual(len(pins), 1)
        self.assertIs(pins[0].resource, work)
        self.assertIs(pins[0].connection, work._connection)
        self.assertIs(pins[0].executor, source._executor)
        descriptor = strict_loads(knowledge._journal.binding)
        self.assertEqual(descriptor['workSources'], [{'resourceRef': {
            'id': 'work-one', 'ownerHubId': 'hub-one'},
            'bindingDigest': payload_digest(strict_loads(work._journal.binding))}])
        thread = await work._owner.db(threading.get_ident)
        self.assertNotEqual(thread, threading.get_ident())
        self.assertEqual(await knowledge._owner.db(threading.get_ident), thread)
        await self.host.close(timeout=None)
        self.assertTrue(source._closing.done())
        self.assertIsNone(source._store)
        self.assertTrue(all(not client.is_connected for client in self.host._clients))

    def test_undeclared_foreign_and_mismatched_work_sources_refuse_selection(self):
        original = copy.deepcopy(self.value)
        for change in ('undeclared', 'foreign-hub', 'scope', 'repository'):
            with self.subTest(change=change):
                self.value = copy.deepcopy(original)
                knowledge = self.value['storage']['knowledge']['channels'][0]
                work = self.value['storage']['work']['channels'][0]
                if change == 'undeclared':
                    knowledge['workSources'][0]['id'] = 'absent-work'
                elif change == 'foreign-hub':
                    knowledge['workSources'][0]['ownerHubId'] = 'foreign-hub'
                else:
                    work['scope'] = copy.deepcopy(self.scope)
                    work['repository'] = copy.deepcopy(self.value['storage']['work']['repository'])
                    if change == 'scope':
                        work['scope']['projectId'] = 'other-project'
                    else:
                        work['repository']['localName'] = 'other-repository'
                with self.assertRaises(ContractError):
                    self.selected()
        self.value = original

    async def test_omitted_work_sources_keeps_original_empty_descriptor(self):
        self.value['storage']['knowledge']['channels'][0].pop('workSources')
        self.selection = self.selected()
        self.host._selection = self.selection
        await self.start_host()
        knowledge = next(resource for resource in self.host._resources if type(resource) is KnowledgeStorageResource)
        self.assertEqual(knowledge._work_capture_sources, ())
        self.assertNotIn('workSources', strict_loads(knowledge._journal.binding))
        await self.host.close(timeout=None)
