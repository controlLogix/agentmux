"""Actual owner admission, journal, domain audit and mirror; broker I/O controlled."""
import asyncio
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock,patch

from agentmux_contracts import ContractError,canonical_bytes,strict_loads
from nats.js.errors import APIError,NotFoundError
from hub.fed.board_services import SharedBoardStore
from hub.tests import test_work_board_services as board_tests
from identity.test_authority import ref,NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding,OwnerLedger,StreamIdentity,owner_subject
from state_owner.test_ledger import CREATED
from state_owner.retention import Retention
from . import test_board_allocation_journal as journal_tests
from .board_allocation import BoardAllocationResource,BoardAllocationTarget
from .board_allocation_journal import BoardAllocationJournal
from .board_allocation_owner import BoardAllocationOwner
from .board_owner import BoardActor
from .board_phase_signer import BoardPhaseSigner


class BoardBroker:
    """Controlled exact-subject CAS, including retained deletion headers."""
    _prefix='$JS.API'
    def __init__(self,journal,rid):
        self.journal=journal
        self.entries={}
        self.counter='$KV.am_board.'+rid+'.seq.SH'
        self.entries[self.counter]=SimpleNamespace(subject=self.counter,seq=7,data=b'12',headers=None)
        self.sequence=20
        self.calls=[]
        self.before_publish=None
        self.after_publish=None

    async def stream_info(self,stream):
        if stream!='KV_am_board':return await self.journal.stream_info(stream)
        return SimpleNamespace(config=SimpleNamespace(name='KV_am_board',subjects=['$KV.am_board.>']),
            state=SimpleNamespace(last_seq=self.sequence),created=CREATED)

    async def get_msg(self,stream,**kwargs):
        if stream!='KV_am_board':return await self.journal.get_msg(stream,**kwargs)
        assert kwargs['direct'] is False
        if kwargs['subject'] not in self.entries:raise NotFoundError()
        return self.entries[kwargs['subject']]

    async def publish(self,subject,data,*,headers):
        if not subject.startswith('$KV.'):return await self.journal.publish(subject,data,headers=headers)
        self.calls.append((subject,data,dict(headers)))
        if self.before_publish is not None:await self.before_publish(subject,data,headers)
        assert headers['Nats-Expected-Stream']=='KV_am_board'
        previous=self.entries.get(subject)
        if int(headers['Nats-Expected-Last-Subject-Sequence'])!=(0 if previous is None else previous.seq):
            raise APIError(err_code=10071)
        self.sequence+=1
        self.entries[subject]=SimpleNamespace(subject=subject,seq=self.sequence,data=data,headers=dict(headers))
        if self.after_publish is not None:await self.after_publish(subject,data,headers)
        return SimpleNamespace(stream='KV_am_board',seq=self.sequence)


class AllocationOwnerTests(unittest.IsolatedAsyncioTestCase):
    open=journal_tests.AllocationJournalTests.open
    admit=journal_tests.AllocationJournalTests.admit
    open_allocation=journal_tests.AllocationJournalTests.open_allocation

    def setUp(self):
        journal_tests.AllocationJournalTests.setUp(self)
        for module in ('capability_owner.board_allocation_owner','capability_owner.board_allocation_journal',
                       'capability_owner.board_phase_signer'):
            patch(module+'.datetime',_Clock).start()
        self.domain=board_tests.WorkBoardServices()
        self.domain.setUp();self.addCleanup(self.domain.tearDown)
        self.rid=self.domain.owner.policy.rid_of('falcon')
        self.broker=BoardBroker(self.allocation_js,self.rid)
        self.domain.owner.js=self.broker
        self.domain.owner.kv=AsyncMock(side_effect=AssertionError('legacy KV cannot publish'))
        self.install_owner()

    def install_owner(self):
        target=BoardAllocationTarget(self.rid,'SH',StreamIdentity(CREATED,0))
        binding=OwnerBinding('hub-one','federation-board','task-one','board-prefix',self.binding.scope)
        self.resource=BoardAllocationResource(binding,SharedBoardStore(self.domain.owner),'falcon',target)
        ledger=OwnerLedger(self.broker,stream='OWNER',subject=owner_subject(self.binding),binding=self.binding,
            retention=self.allocation_policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        self.allocation=BoardAllocationJournal(ledger,self.service.reader,owner_service_identity_ref=ref('board-owner'),
            target_binding=target)
        phases=BoardPhaseSigner(self.allocation,self.service.ingress,transport_ref=ref('owner-transport'),
            signing_seed=journal_tests.journal_tests.OWNER_SEED,grants={name:ref(name) for name in
                ('federation-board-dispatch','federation-board-complete')})
        self.owner=BoardAllocationOwner(self.resource,self.allocation,phases,actors=(
            BoardActor(ref('human'),ref('transport'),'peer:nick','operator'),))
        self.addAsyncCleanup(self.owner.close)

    async def request(self,operation='add-one',revision=7,*,title='New card'):
        return await self.admit('federation-board-command',operation,revision,
            {'resourceRef':{**self.target,'revision':revision},'attribution':'operator',
             'input':{'command':'add','title':title,'labels':['one']}})

    async def test_public_allocation_owner_refuses_non_add_without_claim_counter_or_card_effect(self):
        raw=await self.admit('federation-board-command','unsupported-comment',7,
            {'resourceRef':{**self.target,'revision':7},'attribution':'operator',
             'input':{'command':'comment','key':'SH-13','text':'Must not be applied'}})
        counter=self.broker.entries[self.broker.counter]
        before=(counter.seq,counter.data,counter.headers)
        with self.assertRaisesRegex(ContractError,'^board_allocation_journal_invalid$'):
            await self.owner.apply(raw)
        self.assertEqual(self.allocation_js.messages,[])
        self.assertEqual(self.broker.calls,[])
        self.assertEqual(set(self.broker.entries),{self.broker.counter})
        after=self.broker.entries[self.broker.counter]
        self.assertEqual((after.seq,after.data,after.headers),before)
        self.assertEqual(self.domain.store.q('SELECT * FROM fed_audit'),[])
        self.assertEqual(self.domain.store.q('SELECT * FROM p_board_cards'),[])

    async def query(self,original,operation='lookup'):
        if not any(g['ref']==ref('capability-outcome-query') for g in self.record['state']['grants']):
            grant=strict_loads(canonical_bytes(next(g for g in self.record['state']['grants']
                if g['ref']==ref('federation-board-command'))))
            grant.update(ref=ref('capability-outcome-query'),contractId='capability-outcome-query')
            self.record['state']['grants'].append(grant)
            self.js.messages[0].data=canonical_bytes(self.record)
        prior=strict_loads(original)['operation']
        return await self.admit('capability-outcome-query',operation,0,{'resourceRef':self.target,
            'input':{'contractId':'federation-board-command','operationId':prior['operationId'],
                     'payloadDigest':prior['payloadDigest']}})

    async def test_fresh_query_recovers_original_card_and_distinct_receipt_after_expiry_and_later_add(self):
        raw=await self.request()
        original=await self.owner.apply(raw)
        self.assertEqual((original['cardRef']['key'],original['cardRef']['revision']),('SH-13',22))
        self.assertEqual(original['receiptRef']['revision'],6)
        await self.owner.apply(await self.request('later',21))
        await self.restart()
        class LaterClock(_Clock):
            @classmethod
            def now(cls,tz=None):return NOW+timedelta(seconds=40)
        self.claims.update(issuedAt=(NOW+timedelta(seconds=40)).isoformat().replace('+00:00','Z'),
                          expiresAt=(NOW+timedelta(seconds=45)).isoformat().replace('+00:00','Z'))
        with patch('identity.ingress.datetime',LaterClock),patch('identity.authority._utc_now',return_value=LaterClock.now()):
            with self.assertRaises(ContractError):await self.owner.apply(raw)
            result=await self.owner.reconcile(await self.query(raw))
        self.assertEqual(result['cardRef'],original['cardRef'])
        self.assertEqual(result['receiptRef'],original['receiptRef'])
        self.assertEqual(result['card']['key'],'SH-13')
        self.assertEqual(result['outcome'],'applied')
        self.assertEqual(len(self.broker.calls),4)

    async def test_query_recovery_rejects_undispatched_card_and_returns_no_created_card_reference(self):
        async def lost(subject,*args):
            if subject==self.broker.counter:
                self.broker.after_publish=None
                raise TimeoutError()
        self.broker.after_publish=lost
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        result=await self.owner.reconcile(await self.query(raw))
        self.assertEqual(result['outcome'],'rejected')
        self.assertIsNone(result['cardRef']);self.assertIsNone(result['card'])
        self.assertIsNotNone(result['receiptRef'])
        self.assertEqual(len(self.broker.calls),1)

    async def test_query_requires_current_original_prefix_permission_even_for_finished_work(self):
        raw=await self.request()
        await self.owner.apply(raw)
        query=await self.query(raw)
        await self.revoke('federation-board-command')
        with self.assertRaisesRegex(ContractError,'board_allocation_query_refused'):
            await self.owner.reconcile(query)
        self.assertEqual(len(self.broker.calls),2)

    async def test_large_candidate_reserves_later_record_size_before_claim_or_counter_write(self):
        raw=await self.request(title='t'*23000)
        with self.assertRaisesRegex(ContractError,'board_allocation_capacity'):
            await self.owner.apply(raw)
        self.assertEqual(self.allocation_js.messages,[])
        self.assertEqual(self.broker.calls,[])
        self.assertIsNone(await self.allocation.pending())

    async def test_stream_completion_budget_refuses_before_claim_or_counter_write(self):
        self.allocation_policy=Retention(1_048_576,262_144)
        self.allocation_js.config=self.allocation_policy.stream_config(stream='OWNER',subject=owner_subject(self.binding))
        self.install_owner()
        with self.assertRaisesRegex(ContractError,'owner_capacity_reserved'):
            await self.owner.apply(await self.request())
        self.assertEqual(self.allocation_js.messages,[])
        self.assertEqual(self.broker.calls,[])

    async def test_initial_absent_counter_allocates_one_but_tombstoned_counter_refuses(self):
        self.broker.entries.pop(self.broker.counter)
        result=await self.owner.apply(await self.request(revision=0))
        self.assertEqual((result['key'],result['rev']),('SH-1',22))
        self.assertEqual(self.broker.calls[0][2]['Nats-Expected-Last-Subject-Sequence'],'0')
        self.broker.entries[self.broker.counter].headers={'KV-Operation':'DEL'}
        with self.assertRaisesRegex(ContractError,'board_counter_recovery_required'):
            await self.owner.apply(await self.request('after-delete',21))
        self.assertEqual(len(self.broker.calls),2)

    async def test_competing_owner_cannot_increment_while_original_counter_worker_is_owned(self):
        started,release=asyncio.Event(),asyncio.Event()
        async def blocked(subject,*args):
            if subject==self.broker.counter:
                started.set();await release.wait()
        self.broker.before_publish=blocked
        first=self.owner
        original=asyncio.create_task(first.apply(await self.request()))
        await started.wait()
        self.install_owner()
        try:
            with self.assertRaisesRegex(ContractError,'board_allocation_busy'):
                await self.owner.apply(await self.request('competitor'))
            self.assertEqual(len(self.broker.calls),1)
        finally:release.set()
        self.assertEqual((await original)['key'],'SH-13')
        self.assertEqual(len(self.broker.calls),2)

    async def test_withdrawn_caller_cannot_resume_counter_but_maintenance_abandons_card(self):
        async def lost(subject,*args):
            if subject==self.broker.counter:
                self.broker.after_publish=None
                raise TimeoutError()
        self.broker.after_publish=lost
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        await self.revoke('transport')
        await self.restart()
        with self.assertRaises(ContractError):await self.owner.apply(raw)
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['counterRevision'],result['cardRevision']),('rejected',21,None))
        self.assertEqual(len(self.broker.calls),1)

    async def restart(self):
        await self.owner.close()
        self.install_owner()

    async def revoke(self,target):
        self.claims.update(operationId='revoke-'+target,contractId='identity-revoke',grantRef=ref('grant'),
            expectedVersion=len(self.js.messages),payload={'authorityId':'authority-one','targetRef':ref(target)})
        response=strict_loads(await self.service.handle(journal_tests.journal_tests.service_tests.ServiceTests.request(self)))
        self.assertEqual(response['claims']['receipt']['decision'],'allowed')

    async def test_counter_loss_or_recreation_refuses_even_when_stream_sequence_advances(self):
        await self.owner.apply(await self.request())
        original=self.broker.entries[self.broker.counter]
        self.broker.sequence=50
        for replacement in (None,SimpleNamespace(subject=self.broker.counter,seq=49,data=original.data,headers=None)):
            if replacement is None:self.broker.entries.pop(self.broker.counter,None)
            else:self.broker.entries[self.broker.counter]=replacement
            with self.subTest(replacement=replacement is None),self.assertRaisesRegex(ContractError,'board_counter_recovery_required'):
                await self.owner.apply(await self.request('after-reset',0 if replacement is None else 49))
        self.assertEqual(len(self.broker.calls),2)

    async def test_original_caller_withdrawal_before_counter_prevents_both_business_writes(self):
        phase=self.owner._phase
        async def withdrawn(contract,*args,**kwargs):
            group=await phase(contract,*args,**kwargs)
            if contract=='federation-board-dispatch' and group['state']['phase']=='counter-dispatching':
                await self.revoke('transport')
            return group
        with patch.object(self.owner,'_phase',side_effect=withdrawn):
            with self.assertRaises(ContractError):await self.owner.apply(await self.request())
        self.assertEqual(self.broker.calls,[])

    async def test_original_caller_withdrawal_before_card_does_not_repeat_the_counter(self):
        phase=self.owner._phase
        async def withdrawn(contract,*args,**kwargs):
            group=await phase(contract,*args,**kwargs)
            if contract=='federation-board-dispatch' and group['state']['phase']=='card-dispatching':
                await self.revoke('transport')
            return group
        with patch.object(self.owner,'_phase',side_effect=withdrawn):
            with self.assertRaises(ContractError):await self.owner.apply(await self.request())
        self.assertEqual(len(self.broker.calls),1)
        self.assertEqual(self.broker.entries[self.broker.counter].data,b'13')

    async def test_withdrawn_owner_phase_grant_cannot_execute_the_counter(self):
        phase=self.owner._phase
        async def withdrawn(contract,*args,**kwargs):
            group=await phase(contract,*args,**kwargs)
            if contract=='federation-board-dispatch' and group['state']['phase']=='counter-dispatching':
                await self.revoke('federation-board-dispatch')
            return group
        with patch.object(self.owner,'_phase',side_effect=withdrawn):
            with self.assertRaises(ContractError):await self.owner.apply(await self.request())
        self.assertEqual(self.broker.calls,[])

    async def test_published_card_fence_identity_survives_failure_before_its_receipt(self):
        async def refused(subject,*args):
            if '.card.' in subject:
                self.broker.before_publish=None
                raise TimeoutError()
        self.broker.before_publish=refused
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(await self.request())
        phase=self.owner._phase
        async def unavailable(contract,*args,**kwargs):
            observation=kwargs.get('observation')
            if type(observation) is dict and observation.get('stage')=='card' and observation.get('outcome')=='rejected':
                raise RuntimeError('PRIVATE journal unavailable')
            return await phase(contract,*args,**kwargs)
        with patch.object(self.owner,'_phase',side_effect=unavailable):
            with self.assertRaises(RuntimeError):await self.owner.recover_pending()
        fence=self.broker.entries['$KV.am_board.'+self.rid+'.card.SH-13']
        retained=(await self.allocation.pending())['state']['cardFenceId']
        self.assertEqual(fence.headers['Agentmux-Board-Fence'],retained)
        await self.restart()
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['cardRevision']),('rejected',fence.seq))
        self.assertEqual(len(self.broker.calls),3)

    async def test_audit_then_projection_failure_recovers_without_duplicate_audit(self):
        actual=self.domain.owner.db
        mirror=self.resource.board._operations._mirror
        async def failed(fn,*args,**kwargs):
            if fn==mirror:raise RuntimeError('PRIVATE projection unavailable')
            return await actual(fn,*args,**kwargs)
        self.domain.owner.db=failed
        with self.assertRaises(RuntimeError):await self.owner.apply(await self.request())
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),1)
        self.domain.owner.db=actual
        await self.restart()
        self.assertEqual((await self.owner.recover_pending())['outcome'],'applied')
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.domain.store.q1('SELECT rev FROM p_board_cards')['rev'],22)

    async def test_cancelled_add_reply_and_close_keep_original_counter_worker(self):
        started,release=asyncio.Event(),asyncio.Event()
        async def blocked(subject,*args):
            if subject==self.broker.counter:
                started.set();await release.wait()
        self.broker.before_publish=blocked
        reply=asyncio.create_task(self.owner.apply(await self.request()))
        await started.wait()
        reply.cancel()
        with self.assertRaises(asyncio.CancelledError):await reply
        try:
            with self.assertRaisesRegex(ContractError,'board_owner_cleanup_incomplete'):
                await self.owner.close(timeout=.001)
        finally:release.set()
        await self.owner.close()
        self.assertEqual(len(self.broker.calls),2)
        self.assertEqual(len(self.owner._workers),0)
        self.assertIsNone(await self.allocation.pending())

    async def test_add_commits_one_counter_and_card_then_original_replay_keeps_old_revision(self):
        raw=await self.request()
        result=await self.owner.apply(raw)
        self.assertEqual((result['key'],result['rev']),('SH-13',22))
        self.assertEqual(self.broker.entries[self.broker.counter].data,b'13')
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.domain.store.q1('SELECT rev FROM p_board_cards')['rev'],22)
        await self.owner.apply(await self.request('later',21))
        self.assertEqual(await self.owner.apply(raw),result)
        self.assertEqual(len(self.broker.calls),4)
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),2)

    async def test_lost_counter_ack_resumes_same_key_without_incrementing_again(self):
        async def lost(subject,*args):
            if subject==self.broker.counter:
                self.broker.after_publish=None
                raise TimeoutError()
        self.broker.after_publish=lost
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        await self.restart()
        result=await self.owner.apply(raw)
        self.assertEqual((result['key'],result['rev']),('SH-13',22))
        self.assertEqual(sum(subject==self.broker.counter for subject,_,_ in self.broker.calls),1)
        self.assertEqual(len(self.domain.store.q('SELECT * FROM fed_audit')),1)

    async def test_lost_card_ack_recovers_original_revision_after_restart(self):
        async def lost(subject,*args):
            if '.card.' in subject:
                self.broker.after_publish=None
                raise TimeoutError()
        self.broker.after_publish=lost
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        await self.restart()
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['counterRevision'],result['cardRevision']),('applied',21,22))
        self.assertEqual(len(self.broker.calls),2)
        self.assertEqual((await self.owner.apply(raw))['rev'],22)

    async def test_unconfirmed_counter_is_fenced_without_increment_or_card(self):
        async def refused(*args):
            self.broker.before_publish=None
            raise TimeoutError()
        self.broker.before_publish=refused
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['counterRevision'],result['cardRevision']),('rejected',21,None))
        entry=self.broker.entries[self.broker.counter]
        self.assertEqual(entry.data,b'12')
        self.assertIn('Agentmux-Board-Fence',entry.headers)
        self.assertEqual(len(self.broker.entries),1)
        self.assertEqual(self.domain.store.q('SELECT * FROM fed_audit'),[])

    async def test_unconfirmed_first_create_is_fenced_by_retained_tombstone(self):
        async def refused(subject,*args):
            if '.card.' in subject:
                self.broker.before_publish=None
                raise TimeoutError()
        self.broker.before_publish=refused
        raw=await self.request()
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(raw)
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['counterRevision'],result['cardRevision']),('rejected',21,22))
        fence=self.broker.entries['$KV.am_board.'+self.rid+'.card.SH-13']
        self.assertEqual((fence.data,fence.headers['KV-Operation']),(b'','DEL'))
        self.assertNotIn('Nats-Rollup',fence.headers)
        self.assertEqual(fence.headers['Nats-Expected-Last-Subject-Sequence'],'0')
        with self.assertRaisesRegex(ContractError,'board_allocation_rejected'):
            await self.owner.apply(raw)
        self.assertEqual(len(self.broker.calls),3)

    async def test_existing_or_tombstoned_target_refuses_before_counter_dispatch(self):
        subject='$KV.am_board.'+self.rid+'.card.SH-13'
        self.broker.entries[subject]=SimpleNamespace(subject=subject,seq=9,data=b'',headers={'KV-Operation':'DEL'})
        with self.assertRaisesRegex(ContractError,'board_allocation_collision'):
            await self.owner.apply(await self.request())
        self.assertEqual(self.broker.calls,[])
        self.assertEqual(self.broker.entries[self.broker.counter].data,b'12')

    async def test_foreign_tombstone_never_proves_this_fence_won(self):
        async def refused(subject,*args):
            if '.card.' in subject:
                self.broker.before_publish=None
                raise TimeoutError()
        self.broker.before_publish=refused
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(await self.request())
        subject='$KV.am_board.'+self.rid+'.card.SH-13'
        self.broker.sequence+=1
        self.broker.entries[subject]=SimpleNamespace(subject=subject,seq=self.broker.sequence,data=b'',headers={'KV-Operation':'DEL'})
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.recover_pending()
        self.assertIsNotNone(await self.allocation.pending())
        self.assertEqual(len(self.broker.calls),2)

    async def test_pinned_client_empty_tombstone_shape_keeps_foreign_fence_unresolved(self):
        async def refused(subject,*args):
            if '.card.' in subject:
                self.broker.before_publish=None
                raise TimeoutError()
        self.broker.before_publish=refused
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(await self.request())
        subject='$KV.am_board.'+self.rid+'.card.SH-13'
        self.broker.sequence+=1
        self.broker.entries[subject]=SimpleNamespace(subject=subject,seq=self.broker.sequence,
            data=None,headers={'KV-Operation':'DEL'})
        with self.assertRaisesRegex(ContractError,'^board_allocation_outcome_uncertain$'):
            await self.owner.recover_pending()
        self.assertIsNotNone(await self.allocation.pending())
        self.assertEqual(len(self.broker.calls),2)

    async def test_pinned_client_empty_tombstone_shape_preserves_own_fence_identity(self):
        async def refused(subject,*args):
            if '.card.' in subject:
                self.broker.before_publish=None
                raise TimeoutError()
        self.broker.before_publish=refused
        with self.assertRaisesRegex(ContractError,'board_allocation_outcome_uncertain'):
            await self.owner.apply(await self.request())
        phase=self.owner._phase
        async def unavailable(contract,*args,**kwargs):
            observation=kwargs.get('observation')
            if type(observation) is dict and observation.get('stage')=='card' and observation.get('outcome')=='rejected':
                raise RuntimeError('Controlled unavailable receipt')
            return await phase(contract,*args,**kwargs)
        with patch.object(self.owner,'_phase',side_effect=unavailable):
            with self.assertRaises(RuntimeError):await self.owner.recover_pending()
        subject='$KV.am_board.'+self.rid+'.card.SH-13'
        fence=self.broker.entries[subject]
        fence.data=None
        await self.restart()
        result=await self.owner.recover_pending()
        self.assertEqual((result['outcome'],result['cardRevision']),('rejected',fence.seq))
        self.assertEqual(len(self.broker.calls),3)

    async def test_missing_data_without_explicit_tombstone_refuses_source_recovery(self):
        self.broker.entries[self.broker.counter].data=None
        with self.assertRaisesRegex(ContractError,'^board_allocation_source_recovery_required$'):
            await self.owner.apply(await self.request())
        self.assertEqual(self.allocation_js.messages,[])
        self.assertEqual(self.broker.calls,[])

    async def test_pinned_client_deleted_or_purged_empty_counter_refuses_before_claim(self):
        counter=self.broker.entries[self.broker.counter]
        for operation in ('DEL','PURGE'):
            counter.data=None
            counter.headers={'KV-Operation':operation}
            with self.subTest(operation=operation),self.assertRaisesRegex(ContractError,'^board_counter_recovery_required$'):
                await self.owner.apply(await self.request('empty-counter-'+operation.lower()))
        self.assertEqual(self.allocation_js.messages,[])
        self.assertEqual(self.broker.calls,[])
