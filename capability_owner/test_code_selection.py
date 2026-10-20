"""Selected code sources retain scope, caller kinds and current authority."""
import copy
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.plugins.code import Code
from hub.store import Store
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from . import test_knowledge_host as support


class SelectedCodeFixture:
    connection = support.SelectedKnowledgeCompositionFixture.connection
    custody = support.SelectedKnowledgeCompositionFixture.custody
    selected = support.SelectedKnowledgeCompositionFixture.selected
    add_board = support.SelectedKnowledgeCompositionFixture.add_board
    identity_inputs = support.SelectedKnowledgeCompositionFixture.identity_inputs
    authority_record = support.SelectedKnowledgeCompositionFixture.authority_record
    asyncSetUp = support.SelectedKnowledgeCompositionFixture.asyncSetUp

    def setUp(self):
        support.SelectedKnowledgeCompositionFixture.setUp(self)
        self.value['storage']['code'] = self.value['storage'].pop('knowledge')
        self.value['storage']['code']['channels'][0]['resourceRef'] = ref('code-one')
        store = Store(self.value['storage']['code']['source']['database']['path'])
        try:
            for statement in Code.tables:
                store.db.execute(statement)
        finally:
            store.db.close()
        self.selection = self.selected()

    def actor(self):
        return {'identityRef': ref('human'), 'transportRef': ref('transport'), 'caller': 'operator',
            'grants': {'federation-code-' + action: ref('code-' + action)
                for action in ('publish', 'fetched', 'approve', 'read', 'inspect', 'outcome')}}

    def configure_legacy(self):
        self.value['storage']['code']['channels'][0]['legacyActors'] = [self.actor()]
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        next(t for t in state['transports'] if t['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        state['memberships'].append({'ref': ref('code-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, reference in self.actor()['grants'].items():
            state['grants'].append({'ref': reference, 'callerRef': ref('human'), 'actorRef': ref('human'),
                'scope': copy.deepcopy(self.scope), 'contractId': contract, 'resourceId': 'code-one',
                'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None,
                'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        return current


class SelectedCodeSelectionTests(SelectedCodeFixture, unittest.IsolatedAsyncioTestCase):
    def test_exact_source_aliases_are_accepted_and_conflicting_pins_refuse(self):
        code = self.value['storage']['code']
        message = copy.deepcopy(code)
        message['channels'][0].update(peer='alice', resourceRef=ref('messages-one'))
        self.value['storage']['messages'] = message
        self.selected()
        original = copy.deepcopy(self.value)
        changes = {
            'other policy': lambda c: c['source']['policy'].update(sha256='sha256:'+'0'*64),
            'other local peer': lambda c: c.update(localPeer='other'),
            'other repository': lambda c: c['repository'].update(localName='other'),
            'database policy alias': lambda c: c['source']['policy'].update(path=c['source']['database']['path']),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                self.value = copy.deepcopy(original)
                mutate(self.value['storage']['code'])
                with self.assertRaises(ContractError):
                    self.selected()

    def test_foreign_actor_and_wrong_grant_family_refuse(self):
        original = copy.deepcopy(self.value)
        changes = {
            'foreign grant': lambda a: a['grants']['federation-code-publish'].update(ownerHubId='other'),
            'unknown contract': lambda a: a['grants'].update({'federation-knowledge-share': ref('wrong')}),
            'service publish': lambda a: a.update(caller='federation'),
            'operator index': lambda a: a['grants'].update({'federation-code-index': ref('index')}),
            'agent approval': lambda a: a.update(caller='falcon-worker-one'),
            'foreign actor': lambda a: a.update(caller='other-worker-one'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                self.value = copy.deepcopy(original)
                actor = self.actor()
                mutate(actor)
                self.value['storage']['code']['channels'][0]['legacyActors'] = [actor]
                with self.assertRaises(ContractError):
                    self.selected()

    async def test_current_grant_membership_transport_and_human_approval_required(self):
        current = self.configure_legacy()
        async def check(record):
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                    canonical_bytes(record), self.snapshot.sequence))):
                await self.selection.check_storage_authority(self.identity)
        await check(current)
        changes = {
            'revoked grant': lambda s: s['grants'][-1].update(status='revoked'),
            'foreign resource': lambda s: s['grants'][-1].update(resourceId='other'),
            'hard denial': lambda s: s['grants'].append(dict(s['grants'][-1], ref=ref('deny-code'), decision='denied')),
            'revoked membership': lambda s: s['memberships'][-1].update(status='revoked'),
            'revoked transport': lambda s: next(t for t in s['transports'] if t['ref']==ref('transport')).update(status='revoked'),
            'device approval': lambda s: next(i for i in s['identities'] if i['ref']==ref('human')).update(kind='device'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(current)
                mutate(changed['state'])
                with self.assertRaises(ContractError):
                    await check(changed)
