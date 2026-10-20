"""Actual admitted allocation phases over a strict retained owner ledger."""
import unittest

from agentmux_contracts import ContractError,canonical_bytes,strict_loads
from hub.fed.board_services import _BoardOperations
from identity.test_authority import ref
from state_owner.ledger import OwnerLedger,StreamIdentity,owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream,CREATED
from . import test_board_journal as journal_tests
from .board_allocation import BoardAllocationTarget,prepare_allocation
from .board_allocation_journal import BoardAllocationJournal


class AllocationJournalTests(unittest.IsolatedAsyncioTestCase):
    admit=journal_tests.BoardJournalTests.admit
    open=journal_tests.BoardJournalTests.open

    def setUp(self):
        journal_tests.BoardJournalTests.setUp(self)
        self.allocation_policy=Retention(4_194_304,1_048_576)
        self.allocation_js=FakeJetStream(self.allocation_policy)
        self.allocation_js.config=self.allocation_policy.stream_config(stream='OWNER',subject=owner_subject(self.binding))
        self.allocation=self.open_allocation()
        self.phases=0

    def open_allocation(self):
        ledger=OwnerLedger(self.allocation_js,stream='OWNER',subject=owner_subject(self.binding),
            binding=self.binding,retention=self.allocation_policy,stream_identity=StreamIdentity(CREATED,0),
            require_completion_budget=True)
        return BoardAllocationJournal(ledger,self.service.reader,owner_service_identity_ref=ref('board-owner'),
            target_binding=BoardAllocationTarget('r0123456789ab','SH',StreamIdentity(CREATED,0)))

    async def claim(self,*,operation='allocate-one',counter=b'12',revision=7,observed=20):
        payload={'resourceRef':{**self.target,'revision':revision},'attribution':'operator',
            'input':{'command':'add','title':'New card'}}
        raw=await self.admit('federation-board-command',operation,revision,payload)
        prepared=_BoardOperations().prepare_add_input(payload['input'])
        plan=prepare_allocation(self.allocation._target,strict_loads(raw),prepared,
            counter_revision=revision,counter_value=counter,observed_sequence=observed,
            context=None,by='peer:nick',at='2026-10-09T12:00:01Z')
        snapshot=await self.allocation._ledger.current()
        stored=await self.allocation.prepare(raw,expected_sequence=snapshot.sequence,plan=plan)
        return raw,plan,stored

    async def phase(self,contract,*,observation='dispatch'):
        snapshot=await self.allocation._ledger.current()
        state=strict_loads(snapshot.latest.record)['state']
        original=state['original']['operation']
        claim=next(item for item in snapshot.records if strict_loads(item.record)['recordId']==state['claimId'])
        payload={'resourceRef':state['original']['payload']['resourceRef'],
            'journalRef':{**ref('task-one'),'revision':snapshot.sequence},
            'claimRef':self.allocation._ref(claim),'originalOperationId':original['operationId'],
            'originalPayloadDigest':original['payloadDigest'],'candidateDigest':state['plan']['candidateDigest']}
        if contract=='federation-board-complete':
            payload['observationId']=self.allocation._observe(payload['claimRef'],result=observation)
        self.phases+=1
        raw=await self.admit(contract,'allocation-phase-'+str(self.phases),snapshot.sequence,payload,owner=True)
        return await self.allocation.advance(raw,expected_sequence=snapshot.sequence)

    async def finish(self):
        await self.phase('federation-board-dispatch')
        await self.phase('federation-board-complete',observation={'stage':'counter','outcome':'applied','revision':23})
        await self.phase('federation-board-dispatch')
        await self.phase('federation-board-complete',observation={'stage':'card','outcome':'applied','revision':27})
        return await self.phase('federation-board-complete',observation={'stage':'finish','auditDone':True,'projectionDone':True})

    async def test_original_claim_tracks_both_actual_revisions_and_survives_later_add(self):
        raw,plan,claim=await self.claim()
        with self.assertRaisesRegex(ContractError,'board_allocation_pending'):
            await self.allocation.check_card('SH-13')
        await self.allocation.check_card('SH-12')
        terminal=await self.finish()
        state=strict_loads(terminal.record)['state']
        self.assertEqual((state['phase'],state['outcome'],state['counterRevision'],state['cardRevision']),
                         ('finished','applied',23,27))
        await self.allocation.check_card('SH-13')
        await self.claim(operation='later',counter=b'13',revision=23,observed=27)
        restarted=self.open_allocation()
        groups=restarted._read(await restarted._ledger.current())
        original=groups[strict_loads(raw)['operation']['operationId']]
        self.assertEqual((original['state']['cardRevision'],original['latest'].sequence),(27,6))
        replay=await restarted.prepare(raw,expected_sequence=0,plan=plan)
        self.assertTrue(replay.replayed)
        self.assertEqual((replay.sequence,len(self.allocation_js.messages)),(claim.sequence,7))

    async def test_source_rollback_and_second_pending_add_refuse(self):
        await self.claim()
        with self.assertRaisesRegex(ContractError,'board_allocation_busy'):
            await self.claim(operation='competing')
        await self.finish()
        before=len(self.allocation_js.messages)
        with self.assertRaises(ContractError):
            await self.claim(operation='rollback',counter=b'13',revision=23,observed=23)
        self.assertEqual(len(self.allocation_js.messages),before)

    async def test_undispatched_card_can_be_abandoned_but_never_after_dispatch(self):
        await self.claim()
        await self.phase('federation-board-dispatch')
        await self.phase('federation-board-complete',observation={'stage':'counter','outcome':'applied','revision':23})
        stored=await self.phase('federation-board-complete',observation={'stage':'abandon'})
        state=strict_loads(stored.record)['state']
        self.assertEqual((state['outcome'],state['counterRevision'],state['cardRevision']),('rejected',23,None))
        await self.claim(operation='second',counter=b'13',revision=23,observed=23)
        await self.phase('federation-board-dispatch')
        await self.phase('federation-board-complete',observation={'stage':'counter','outcome':'applied','revision':24})
        await self.phase('federation-board-dispatch')
        with self.assertRaises(ContractError):
            await self.phase('federation-board-complete',observation={'stage':'abandon'})

    async def test_uncertain_counter_keeps_prefix_frozen_until_actual_fence_revision(self):
        await self.claim()
        await self.phase('federation-board-dispatch')
        await self.phase('federation-board-complete',observation=None)
        with self.assertRaisesRegex(ContractError,'board_allocation_pending'):
            await self.allocation.check_card('SH-13')
        with self.assertRaises(ContractError):
            await self.phase('federation-board-complete',observation={'stage':'counter','outcome':'rejected','revision':7})
        stored=await self.phase('federation-board-complete',observation={'stage':'counter','outcome':'rejected','revision':23})
        self.assertEqual(strict_loads(stored.record)['state']['phase'],'finished')

    async def test_lost_phase_ack_replays_original_identity_without_another_append(self):
        await self.claim()
        self.allocation_js.lose_ack=True
        with self.assertRaisesRegex(ContractError,'owner_commit_uncertain'):
            await self.phase('federation-board-dispatch')
        state=strict_loads(self.allocation_js.messages[-1].data)['state']
        replay=await self.allocation.advance(canonical_bytes(state['phaseEnvelope']),expected_sequence=1)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.allocation_js.messages),2)
