"""Actual enrolled journal transitions; only retained broker I/O is controlled."""
import base64
import copy
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from hub.fed.board_services import _BoardOperations
from identity.test_authority import ref, NOW, SEED
from identity import test_service as service_tests
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED
from .board_journal import BoardOperationJournal, claim_marker
from .board_target import BoardTargetBinding

OWNER_SEED = bytes([53])*32


class BoardJournalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        service_tests.ServiceTests.setUp(self)
        patch('identity.authority._utc_now',return_value=NOW).start()
        patch('capability_owner.board_journal.datetime',service_tests._Clock).start()
        self.scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None}
        state=self.record['state']
        member=copy.deepcopy(state['memberships'][0]);member.update(ref=ref('board-member'),scope=self.scope)
        state['memberships'].append(member)
        state['identities'].append({'ref':ref('board-owner'),'principalId':'board-owner-one',
            'kind':'service','status':'active','externalIdentity':None})
        member=copy.deepcopy(member);member.update(ref=ref('owner-member'),identityRef=ref('board-owner'))
        state['memberships'].append(member)
        transport=copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('owner-transport'),identityRef=ref('board-owner'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(OWNER_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        for name in ('capability-storage-write','federation-board-command',
                     'federation-board-dispatch','federation-board-complete'):
            grant=copy.deepcopy(state['grants'][0]);grant.update(ref=ref(name),scope=self.scope,
                contractId=name,resourceId='task-one')
            if name in ('federation-board-dispatch','federation-board-complete'):
                grant.update(callerRef=ref('board-owner'),actorRef=ref('board-owner'))
            state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        self.journal_js=FakeJetStream(self.policy)
        self.binding=OwnerBinding('hub-one','federation-board-operations','task-one','attempt',canonical_bytes(self.scope))
        self.journal_js.config=self.policy.stream_config(stream='OWNER',subject=owner_subject(self.binding))
        self.journal=self.open()
        self.target={**ref('task-one'),'revision':7}

    def open(self, **changes):
        options=dict(owner_service_identity_ref=ref('board-owner'),
            target_binding=BoardTargetBinding('r0123456789ab','SH-1',StreamIdentity(CREATED,0)));options.update(changes)
        ledger=OwnerLedger(self.journal_js,stream='OWNER',subject=owner_subject(self.binding),
            binding=self.binding,retention=self.policy,stream_identity=StreamIdentity(CREATED,0),
            require_completion_budget=True)
        return BoardOperationJournal(ledger,self.service.reader,**options)

    async def admit(self, contract, operation, expected, payload, *, owner=False):
        claims=copy.deepcopy(self.claims)
        claims.update(contractId=contract,operationId=operation,expectedVersion=expected,
                      grantRef=ref(contract),payload=payload)
        if owner:claims['transportRef']=ref('owner-transport')
        raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
            'signature':sign_claims(claims,OWNER_SEED if owner else bytes(reversed(SEED)))})
        admitted=await self.service.ingress.admit(raw,cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed',admitted.decision.reason)
        return admitted.envelope

    async def prepare(self, *, operation='board-write', expected_sequence=0, observed_sequence=7):
        raw=await self.admit('federation-board-command',operation,7,
            {'resourceRef':self.target,'attribution':'operator',
             'input':{'command':'comment','key':'SH-1','text':'one'}})
        card={'key':'SH-1','rid':'r0123456789ab','title':'Existing','status':'todo',
              '_agentmuxOperation':claim_marker(strict_loads(raw))}
        candidate=_BoardOperations().prepare_change(None,card['rid'],card,
            {'command':'comment','text':'one'},by='peer:nick',at='2026-10-09T12:00:01Z')
        stored=await self.journal.prepare(raw,expected_sequence=expected_sequence,
            candidate=candidate,target_ref=self.target,observed_sequence=observed_sequence)
        return raw,candidate,stored

    async def phase(self, contract, operation, *, observation=None, change=None):
        snapshot=await self.journal._ledger.current()
        state=strict_loads(snapshot.latest.record)['state']
        original=state['original']['operation']
        claim=next(s for s in snapshot.records if strict_loads(s.record)['recordId']==state['claimId'])
        payload={'resourceRef':state['targetRef'],
            'journalRef':{**ref('task-one'),'revision':snapshot.sequence},
            'claimRef':{'id':state['claimId'],'ownerHubId':'hub-one','revision':claim.sequence},
            'originalOperationId':original['operationId'],'originalPayloadDigest':original['payloadDigest'],
            'candidateDigest':state['candidateDigest']}
        if observation is not None:payload['observationId']=observation
        if change:payload.update(change)
        return await self.admit(contract,operation,snapshot.sequence,payload,owner=True)

    def observe(self, original, result):
        state=strict_loads(original.record)['state']
        claim={'id':state['claimId'],'ownerHubId':'hub-one','revision':original.sequence}
        return self.journal._observe(claim,result=result)

    async def test_distinct_owner_operations_resolve_original_after_restart_and_later_claim(self):
        raw,candidate,claim=await self.prepare()
        op=strict_loads(raw)['operation']
        pending=await self.journal.outcome(op['operationId'],op['payloadDigest'])
        self.assertEqual((pending.phase,pending.result),('prepared',None))
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        observed=self.observe(claim,{'outcome':'applied','resourceRef':{**self.target,'revision':23},
                                   'auditDone':True,'projectionDone':True})
        complete=await self.phase('federation-board-complete','complete-one',observation=observed)
        await self.journal.advance(complete,expected_sequence=2)
        await self.prepare(operation='later-write',expected_sequence=3,observed_sequence=23)
        restarted=self.open()
        result=await restarted.outcome(op['operationId'],op['payloadDigest'])
        self.assertEqual((result.phase,result.result),('finished','applied'))
        self.assertEqual(strict_loads(result.resource_ref)['revision'],23)
        replay=await restarted.prepare(raw,expected_sequence=0,candidate=candidate,target_ref=self.target,observed_sequence=7)
        self.assertTrue(replay.replayed)
        self.assertEqual((replay.sequence,len(self.journal_js.messages)),(1,4))

    async def test_pending_claim_blocks_another_writer_and_completion_cannot_skip_dispatch(self):
        _,_,claim=await self.prepare()
        with self.assertRaisesRegex(ContractError,'board_journal_busy'):
            await self.prepare(operation='other-write',expected_sequence=1)
        observed=self.observe(claim,{'outcome':'applied','resourceRef':self.target,
                                   'auditDone':True,'projectionDone':True})
        complete=await self.phase('federation-board-complete','skip-dispatch',observation=observed)
        with self.assertRaisesRegex(ContractError,'board_journal_invalid'):
            await self.journal.advance(complete,expected_sequence=1)
        self.assertEqual(len(self.journal_js.messages),1)

    async def test_missing_observation_and_wrong_owner_do_not_complete(self):
        await self.prepare()
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        wrong=self.open(owner_service_identity_ref=ref('service'))
        with self.assertRaisesRegex(ContractError,'board_journal_access_refused'):
            await wrong.advance(dispatch,expected_sequence=1)
        await self.journal.advance(dispatch,expected_sequence=1)
        complete=await self.phase('federation-board-complete','complete-one',observation='missing')
        with self.assertRaisesRegex(ContractError,'board_observation_unavailable'):
            await self.journal.advance(complete,expected_sequence=2)
        self.assertEqual(len(self.journal_js.messages),2)

    async def test_lost_completion_ack_replays_same_phase_without_another_append(self):
        raw,_,claim=await self.prepare()
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        observed=self.observe(claim,{'outcome':'applied','resourceRef':{**self.target,'revision':23},
                                   'auditDone':True,'projectionDone':True})
        complete=await self.phase('federation-board-complete','complete-one',observation=observed)
        self.journal_js.lose_ack=True
        with self.assertRaisesRegex(ContractError,'owner_commit_uncertain'):
            await self.journal.advance(complete,expected_sequence=2)
        replay=await self.open().advance(complete,expected_sequence=2)
        self.assertEqual((replay.sequence,len(self.journal_js.messages)),(3,3))
        original=strict_loads(raw)['operation']
        result=await self.open().outcome(original['operationId'],original['payloadDigest'])
        self.assertEqual(strict_loads(result.resource_ref)['revision'],23)

    async def test_fresh_ingress_delivery_replays_original_operation_without_reapplying(self):
        raw,_,_=await self.prepare()
        newer,_,replay=await self.prepare()
        self.assertNotEqual(raw,newer)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.journal_js.messages),1)
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        message=strict_loads(dispatch)
        fresh=await self.admit(message['contractId'],'dispatch-one',1,message['payload'],owner=True)
        self.assertNotEqual(dispatch,fresh)
        self.assertTrue((await self.journal.advance(fresh,expected_sequence=1)).replayed)
        self.assertEqual(len(self.journal_js.messages),2)

    async def test_uncertainty_and_pending_projection_keep_card_frozen(self):
        raw,_,claim=await self.prepare()
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        unresolved=self.observe(claim,None)
        query=await self.phase('federation-board-complete','uncertain-one',observation=unresolved)
        await self.journal.advance(query,expected_sequence=2)
        op=strict_loads(raw)['operation']
        result=await self.journal.outcome(op['operationId'],op['payloadDigest'])
        self.assertEqual((result.phase,result.result,result.resource_ref),('uncertain',None,None))
        with self.assertRaisesRegex(ContractError,'board_journal_busy'):
            await self.prepare(operation='other-write',expected_sequence=3)
        applied={'outcome':'applied','resourceRef':{**self.target,'revision':23},
                 'auditDone':True,'projectionDone':False}
        observed=self.observe(claim,applied)
        complete=await self.phase('federation-board-complete','settled-one',observation=observed)
        await self.journal.advance(complete,expected_sequence=3)
        with self.assertRaisesRegex(ContractError,'board_journal_busy'):
            await self.prepare(operation='other-write',expected_sequence=4)
        observed=self.observe(claim,{**applied,'projectionDone':True})
        complete=await self.phase('federation-board-complete','finished-one',observation=observed)
        await self.journal.advance(complete,expected_sequence=4)
        await self.prepare(operation='other-write',expected_sequence=5,observed_sequence=23)
        self.assertEqual(len(self.journal_js.messages),6)

    async def test_retained_result_cannot_be_replaced_or_degraded(self):
        _,_,claim=await self.prepare()
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        result={'outcome':'applied','resourceRef':{**self.target,'revision':23},
                'auditDone':True,'projectionDone':False}
        observed=self.observe(claim,result)
        complete=await self.phase('federation-board-complete','settled-one',observation=observed)
        await self.journal.advance(complete,expected_sequence=2)
        for suffix,changed in (('revision',{**result,'resourceRef':{**self.target,'revision':24}}),
                               ('audit',{**result,'auditDone':False}),('uncertain',None)):
            observed=self.observe(claim,changed)
            complete=await self.phase('federation-board-complete','replace-'+suffix,observation=observed)
            with self.subTest(suffix=suffix),self.assertRaisesRegex(ContractError,'board_journal_invalid'):
                await self.journal.advance(complete,expected_sequence=3)
        self.assertEqual(len(self.journal_js.messages),3)

    async def test_restart_cannot_rebind_retained_claim_to_another_card_or_stream(self):
        raw,_,_=await self.prepare()
        op=strict_loads(raw)['operation']
        from datetime import timedelta
        for target in (BoardTargetBinding('r0123456789ab','SH-2',StreamIdentity(CREATED,0)),
                       BoardTargetBinding('r0123456789ab','SH-1',StreamIdentity(CREATED+timedelta(seconds=1),0)),
                       BoardTargetBinding('r0123456789ab','SH-1',StreamIdentity(CREATED,0),'other')):
            with self.subTest(target=target),self.assertRaisesRegex(ContractError,'board_journal_invalid'):
                await self.open(target_binding=target).outcome(op['operationId'],op['payloadDigest'])

    async def test_candidate_cannot_change_enrolled_repository_or_card(self):
        raw=await self.admit('federation-board-command','wrong-card',7,
            {'resourceRef':self.target,'attribution':'operator',
             'input':{'command':'comment','key':'SH-1','text':'one'}})
        for changed in ({'key':'SH-2'},{'rid':'raaaaaaaaaaaa'}):
            card={'key':'SH-1','rid':'r0123456789ab','status':'todo',**changed,
                  '_agentmuxOperation':claim_marker(strict_loads(raw))}
            candidate=_BoardOperations().prepare_change(None,card['rid'],card,
                {'command':'comment','text':'one'},by='peer:nick',at='2026-10-09T12:00:01Z')
            with self.subTest(changed=changed),self.assertRaisesRegex(ContractError,'board_journal_invalid'):
                await self.journal.prepare(raw,expected_sequence=0,candidate=candidate,
                    target_ref=self.target,observed_sequence=7)
        self.assertEqual(self.journal_js.messages,[])

    async def test_later_source_observation_cannot_rollback_but_caller_target_can_be_stale(self):
        _,_,claim=await self.prepare()
        dispatch=await self.phase('federation-board-dispatch','dispatch-one')
        await self.journal.advance(dispatch,expected_sequence=1)
        observed=self.observe(claim,{'outcome':'applied','resourceRef':{**self.target,'revision':23},
                                   'auditDone':True,'projectionDone':True})
        complete=await self.phase('federation-board-complete','complete-one',observation=observed)
        await self.journal.advance(complete,expected_sequence=2)
        restarted=self.open()
        self.assertEqual(await restarted.source_floor(),23)
        self.journal=restarted
        with self.assertRaisesRegex(ContractError,'board_source_recovery_required'):
            await self.prepare(operation='stale-source',expected_sequence=3,observed_sequence=7)
        self.assertEqual(len(self.journal_js.messages),3)
        _,_,new=await self.prepare(operation='stale-caller',expected_sequence=3,observed_sequence=23)
        self.assertEqual(strict_loads(new.record)['operation']['expectedVersion'],7)
