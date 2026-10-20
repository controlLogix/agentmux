"""Existing board owner and enrolled receiver; only broker I/O is controlled."""
import base64
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.board_services import SharedBoardStore, _BoardOperations
from hub.fed.session import FederationSession
from hub.tests import test_work_board_services as board_tests
from hub.tests.test_fed_unit import policy
from identity import test_capability_admission as admitted_tests
from identity.test_authority import ref
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.test_ledger import CREATED
from .federation_board import FederationBoardResource
from .receiver import CapabilityReceiver
from . import test_reply_service as reply_tests


class PreparedBoardChangeTests(unittest.TestCase):
    def setUp(self):
        self.operations=_BoardOperations()
        self.card={'key':'SH-1','rid':'r0123456789ab','status':'todo','title':'Existing',
            'comments':[{'text':'Existing comment'}],
            'history':[{'what':str(i)} for i in range(55)],
            'unknownFutureField':{'nested':[None,42,'preserved']}}

    def prepare(self,change):
        return self.operations.prepare_change(None,self.card['rid'],self.card,change,
            by='peer:nick',at='2026-10-16T12:00:00.123Z')

    def test_frozen_comment_candidate_reuses_exact_bytes_and_preserves_source(self):
        original=copy.deepcopy(self.card)
        first=self.prepare({'command':'comment','text':'new comment'})
        self.assertEqual(first.value,self.prepare({'command':'comment','text':'new comment'}).value)
        self.assertEqual(self.card,original)
        result=first.card
        self.assertEqual(result['unknownFutureField'],original['unknownFutureField'])
        self.assertEqual((result['key'],result['rid']),('SH-1','r0123456789ab'))
        self.assertEqual(result['comments'][-1],{'by':'peer:nick',
            'at':'2026-10-16T12:00:00.123Z','text':'new comment'})
        self.assertEqual(len(result['history']),50)
        self.assertEqual(result['history'][-1],{'by':'peer:nick',
            'at':'2026-10-16T12:00:00.123Z','what':'comment'})
        result['comments'].clear()
        self.assertEqual(len(first.card['comments']),2)

    def test_existing_move_assign_and_claim_rules_prepare_without_io(self):
        self.assertEqual(self.prepare({'command':'move','status':'review'}).card['status'],'review')
        self.assertEqual(self.prepare({'command':'assign','to':'peer:alice'}).card['assignee'],'peer:alice')
        claimed=self.prepare({'command':'claim'}).card
        self.assertEqual((claimed['status'],claimed['assignee']),('doing','peer:nick'))
        self.card.update(status='doing',assignee='peer:alice')
        from hub.store import HubError
        with self.assertRaisesRegex(HubError,'already being done'):
            self.prepare({'command':'claim'})

    def test_preparation_keeps_actual_redaction_and_blocking(self):
        from hub.fed.guard import Refused
        candidate=self.prepare({'command':'comment','text':'ghp_'+'a'*36})
        self.assertNotIn('ghp_',candidate.value.decode())
        self.assertIn('github_token',candidate.kinds)
        with self.assertRaises(Refused):
            self.prepare({'command':'comment','text':'-----BEGIN PRIVATE KEY-----'})
        self.assertEqual(len(self.card['comments']),1)

    def test_closed_changes_cannot_replace_arbitrary_card_fields(self):
        from hub.store import HubError
        for change in ({'command':'replace','value':{}},
                       {'command':'move','status':'done','history':[]},
                       {'command':'move','status':'unknown'},
                       {'command':'comment','text':{'status':'done'}}):
            with self.subTest(change=change),self.assertRaises(HubError):
                self.prepare(change)


class FederationBoardTests(unittest.IsolatedAsyncioTestCase):
    request=admitted_tests.CapabilityAdmissionTests.request
    admit=admitted_tests.CapabilityAdmissionTests.admit

    def setUp(self):
        admitted_tests.CapabilityAdmissionTests.setUp(self)
        self.legacy=board_tests.WorkBoardServices()
        self.legacy.setUp()
        self.addCleanup(self.legacy.tearDown)
        owner=self.legacy.owner
        self.rid=owner.policy.rid_of('falcon')
        self.card={'key':'SH-1','rid':self.rid,'title':'Existing card','status':'todo',
            'comments':[{'by':'peer:alice','text':'Existing comment'}],
            'history':[{'by':'peer:nick','what':'created'}],
            'unknownFutureField':{'nested':[None,42,'preserved']}}
        self.raw=json.dumps(self.card,indent=2).encode()
        self.entry=SimpleNamespace(bucket='am_board',key=self.rid+'.card.SH-1',value=self.raw,revision=7)
        self.kv=SimpleNamespace(get=AsyncMock(side_effect=lambda key:self.entry),update=AsyncMock())
        owner.kv=AsyncMock(return_value=self.kv)
        self.info=SimpleNamespace(config=SimpleNamespace(name='KV_am_board',subjects=['$KV.am_board.>']),
            created=CREATED,state=SimpleNamespace(last_seq=7))
        owner.js=SimpleNamespace(stream_info=AsyncMock(side_effect=lambda stream:self.info),
                                 key_value=AsyncMock(return_value=self.kv))
        board=SharedBoardStore(owner)
        board._operations._mirror(owner,self.rid,'SH-1',self.card,7)
        self.mirror=self.legacy.store.q('SELECT * FROM p_board_cards')
        scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None}
        self.record['state']['grants'][1]['scope']=copy.deepcopy(scope)
        membership=copy.deepcopy(self.record['state']['memberships'][0])
        membership.update(ref=ref('board-member'),scope=copy.deepcopy(scope))
        self.record['state']['memberships'].append(membership)
        self.js.messages[0].data=canonical_bytes(self.record)
        binding=OwnerBinding('hub-one','federation-board','task-one','board-card',canonical_bytes(scope))
        self.board_resource=FederationBoardResource(binding,board,'falcon',self.rid,'SH-1',
            StreamIdentity(CREATED,7))
        self.receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[self.board_resource])
        self.addAsyncCleanup(self.receiver.close)
        self.claims.update(expectedVersion=7,payload={'resourceRef':{**ref('task-one'),'revision':7},'input':{}})

    async def read(self):
        admitted=await self.admit()
        self.assertEqual(admitted.decision.outcome,'allowed')
        return await self.receiver.handle(admitted.envelope)

    async def test_original_card_bytes_ids_history_and_sql_projection_are_preserved(self):
        response=await self.read()
        content=strict_loads(response.payload)
        self.assertEqual(base64.b64decode(content['data']),self.raw)
        self.assertEqual(content['resourceRef']['revision'],7)
        self.assertEqual(strict_loads(base64.b64decode(content['data'])),self.card)
        self.assertEqual(self.legacy.store.q('SELECT * FROM p_board_cards'),self.mirror)
        self.kv.update.assert_not_awaited()
        self.legacy.owner.js.key_value.assert_awaited_with('am_board')
        self.legacy.owner.kv.assert_not_awaited()
        self.kv.get.assert_awaited_with(self.rid+'.card.SH-1')
        self.assertNotIn('SH-1',repr(self.board_resource))

    async def test_changed_card_revision_is_not_the_requested_snapshot(self):
        self.entry.revision=8
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):await self.read()
        self.kv.update.assert_not_awaited()

    async def test_repository_withdrawal_during_read_refuses_disclosure(self):
        async def withdraw(key):
            self.legacy.owner.policy=policy(repos={})
            return self.entry
        self.kv.get.side_effect=withdraw
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):await self.read()

    async def test_binding_change_during_final_authority_check_refuses_disclosure(self):
        original_policy=self.legacy.owner.policy
        original_session=self.legacy.owner.session
        actual=self.service.reader.evaluate
        for variant in ('repository','session','closed'):
            self.legacy.owner.policy=original_policy
            self.legacy.owner.session=original_session
            original_session.closing=False
            calls=0
            async def evaluate(*args,**kwargs):
                nonlocal calls
                result=await actual(*args,**kwargs)
                calls+=1
                if calls==2:
                    if variant=='repository':self.legacy.owner.policy=policy(repos={})
                    elif variant=='session':self.legacy.owner.session=FederationSession()
                    else:await original_session.close()
                return result
            with self.subTest(variant=variant),patch.object(self.service.reader,'evaluate',side_effect=evaluate):
                with self.assertRaises(ContractError):await self.read()
                self.assertEqual(calls,2)
        self.legacy.owner.policy=original_policy
        self.legacy.owner.session=original_session

    async def test_current_grant_revocation_during_read_refuses_disclosure(self):
        async def revoke(key):
            self.record['state']['grants'][1]['status']='revoked'
            self.js.messages[0].data=canonical_bytes(self.record)
            return self.entry
        self.kv.get.side_effect=revoke
        with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):await self.read()
        self.kv.get.assert_awaited_once()

    async def test_original_session_replacement_refuses_before_broker_read(self):
        self.legacy.owner.session=FederationSession()
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):await self.read()
        self.kv.get.assert_not_awaited()

    async def test_stream_recreation_or_rollback_refuses_before_card_read(self):
        original=copy.deepcopy(self.info)
        for variant in ('created','sequence','subjects'):
            self.info=copy.deepcopy(original)
            if variant=='created':self.info.created=CREATED.replace(year=2027)
            elif variant=='sequence':self.info.state.last_seq=6
            else:self.info.config.subjects=['$KV.other.>']
            with self.subTest(variant=variant),self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):
                await self.read()
        self.kv.get.assert_not_awaited()

    async def test_observed_stream_sequence_cannot_move_backwards(self):
        self.info.state.last_seq=9
        await self.read()
        self.info.state.last_seq=8
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):await self.read()
        self.assertEqual(self.kv.get.await_count,1)

    async def test_card_identity_substitution_is_refused(self):
        for field,value in (('key','SH-2'),('rid','r'+'f'*12)):
            self.entry.value=canonical_bytes({**self.card,field:value})
            with self.subTest(field=field),self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):
                await self.read()

    async def test_unimplemented_write_does_not_mutate_legacy_card_or_projection(self):
        self.record['state']['grants'][1]['contractId']='capability-storage-write'
        self.js.messages[0].data=canonical_bytes(self.record)
        self.claims.update(contractId='capability-storage-write',payload={
            'resourceRef':{**ref('task-one'),'revision':7},'input':{'value':{'command':'move','status':'doing'}}})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):await self.read()
        self.kv.get.assert_not_awaited()
        self.kv.update.assert_not_awaited()
        self.assertEqual(self.legacy.store.q('SELECT * FROM p_board_cards'),self.mirror)


class BoardReplyServiceTests(reply_tests.StorageReadContract, unittest.IsolatedAsyncioTestCase):
    """Use real enrollment and signing around the existing board owner."""
    from . import test_reply_service as reply_tests
    request=reply_tests.ReplyServiceTests.request
    enroll=reply_tests.ReplyServiceTests.enroll
    signed=reply_tests.ReplyServiceTests.signed
    call=reply_tests.ReplyServiceTests.call
    verify=reply_tests.ReplyServiceTests.verify

    def setUp(self):
        self.reply_tests.ReplyServiceTests.setUp(self)
        scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None}
        for name in ('grant','policy'):
            self.row['facts'][name]['scope']=copy.deepcopy(scope)
        state=self.record['state']
        for grant in state['grants']:
            if grant['contractId'] in ('capability-storage-read','native-authority-prepare-domain-call'):
                grant['scope']=copy.deepcopy(scope)
        for original in tuple(state['memberships']):
            membership=copy.deepcopy(original)
            membership['ref']={**membership['ref'],'id':membership['ref']['id']+'-project'}
            membership['scope']=copy.deepcopy(scope)
            state['memberships'].append(membership)
        self.js.messages[0].data=canonical_bytes(self.record)

    async def asyncSetUp(self):
        await self.reply_tests.ReplyServiceTests.asyncSetUp(self)
        self.legacy=board_tests.WorkBoardServices()
        self.legacy.setUp()
        self.addCleanup(self.legacy.tearDown)
        owner=self.legacy.owner
        rid=owner.policy.rid_of('falcon')
        raw=canonical_bytes({'key':'SH-1','rid':rid,'status':'todo','history':[]})
        entry=SimpleNamespace(bucket='am_board',key=rid+'.card.SH-1',value=raw,revision=1)
        self.kv=SimpleNamespace(get=AsyncMock(return_value=entry))
        owner.kv=AsyncMock(return_value=self.kv)
        info=SimpleNamespace(config=SimpleNamespace(name='KV_am_board',subjects=['$KV.am_board.>']),
            created=CREATED,state=SimpleNamespace(last_seq=1))
        owner.js=SimpleNamespace(stream_info=AsyncMock(return_value=info),
                                 key_value=AsyncMock(return_value=self.kv))
        binding=OwnerBinding('hub-one','federation-board','task-one','board-card',
            canonical_bytes(self.row['facts']['grant']['scope']))
        resource=FederationBoardResource(binding,SharedBoardStore(owner),'falcon',rid,'SH-1',StreamIdentity(CREATED,1))
        self.reply_service._receiver._resources['task-one']=resource
        self.raw=raw

    async def contract_seed(self):
        return self.raw

    async def test_existing_board_read_has_a_verified_signed_reply(self):
        response=await self.call()
        self.assertEqual(base64.b64decode(strict_loads(self.verify(response))['data']),self.raw)
        self.kv.get.assert_awaited_once()

    async def test_owner_change_during_final_service_admission_withholds_signature(self):
        owner=self.legacy.owner
        original_policy,original_session=owner.policy,owner.session
        actual=self.reply_service._admit
        for variant in ('repository','session','closed'):
            owner.policy,owner.session=original_policy,original_session
            original_session.closing=False
            calls=0
            self.kv.get.reset_mock()
            async def admit(*args,**kwargs):
                nonlocal calls
                result=await actual(*args,**kwargs)
                calls+=1
                if calls==2:
                    if variant=='repository':owner.policy=policy(repos={})
                    elif variant=='session':owner.session=FederationSession()
                    else:await original_session.close()
                return result
            with self.subTest(variant=variant),patch.object(self.reply_service,'_admit',side_effect=admit):
                with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                    await self.call()
                self.assertEqual(calls,2)
                self.kv.get.assert_awaited_once()
        owner.policy,owner.session=original_policy,original_session
