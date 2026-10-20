"""Native board writes and recovery use actual enrolled wrappers and owner phases."""
import copy
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.test_authority import ref, SEED, NOW
from . import test_board_native_journal as native_tests
from . import test_board_owner as owner_tests
from .board_owner import BoardMutationOwner
from .board_phase_signer import BoardPhaseSigner
from .federation_board import FederationBoardResource


class NativeBoardOwnerTests(unittest.IsolatedAsyncioTestCase):
    open=native_tests.NativeBoardJournalTests.open
    admit=native_tests.NativeBoardJournalTests.admit
    set_row=native_tests.NativeBoardJournalTests.set_row
    asyncSetUp=native_tests.NativeBoardJournalTests.asyncSetUp
    install_board=owner_tests.BoardOwnerTests.install_board

    def setUp(self):
        native_tests.NativeBoardJournalTests.setUp(self)
        self.install_board()
        for row in (self.parent,self.row):
            row['facts']['grant']['actions'].append('inspect')
            row['facts']['policy']['decisions'].append({'access':{
                'action':'inspect','resourceClass':'outcome','resourceId':'task-one'},'outcome':'allow'})
            row['facts']['domainBindings'].append({'id':'board-outcome','contractId':'capability-outcome-query',
                'action':'inspect','resourceClass':'outcome','resourceIds':['task-one']})
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess']=[copy.deepcopy(item['access'])
            for item in self.parent['facts']['policy']['decisions']]
        grant=copy.deepcopy(self.record['state']['grants'][0]);grant.update(ref=ref('capability-outcome-query'),
            contractId='capability-outcome-query',resourceId='task-one',scope=copy.deepcopy(self.scope))
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)

    def wrapper(self, raw):
        result=strict_loads(native_tests.NativeBoardJournalTests.wrapper(self,raw))
        now=getattr(self,'now',NOW)
        result['claims'].update(resourceRef=strict_loads(raw)['payload']['resourceRef'],
            issuedAt=now.isoformat().replace('+00:00','Z'),
            validUntil=(now+timedelta(seconds=4)).isoformat().replace('+00:00','Z'))
        if strict_loads(raw)['contractId']=='capability-outcome-query':
            result['claims'].update(requestContractId='capability-outcome-query',
                replyContractId='capability-outcome-query-reply',serviceId='outcome-owner')
        result['signature']=sign_claims(result['claims'],SEED)
        return canonical_bytes(result)

    async def write(self, *, expected=7, command=None):
        target={**self.target,'revision':expected}
        return await self.admit('capability-storage-write','native-board-write',expected,
            {'resourceRef':target,'input':{'value':command or {'command':'comment','text':'one'}}})

    async def query(self, raw):
        operation=strict_loads(raw)['operation']
        return await self.admit('capability-outcome-query','recover-board-write',7,
            {'resourceRef':self.target,'input':{'operationId':operation['operationId'],
             'payloadDigest':operation['payloadDigest'],'contractId':'capability-storage-write'}})

    async def restart_owner(self):
        await self.owner.close()
        old=self.resource
        self.resource=FederationBoardResource(old.binding,old.board,old.repository,
            old.repository_id,old.card_key,old.stream_identity)
        self.journal=self.open(target_binding=self.journal._target)
        self.signer=BoardPhaseSigner(self.journal,self.service.ingress,transport_ref=ref('owner-transport'),
            signing_seed=native_tests.journal_tests.OWNER_SEED,grants={name:ref(name) for name in
                ('federation-board-dispatch','federation-board-complete')})
        self.owner=BoardMutationOwner(self.resource,self.journal,self.signer,actors=self.owner._actors)
        self.addAsyncCleanup(self.owner.close)

    async def test_restart_recovers_lost_card_ack_without_process_observations(self):
        actual=self.kv.update.side_effect
        async def lost_ack(*args,**kwargs):
            await actual(*args,**kwargs)
            raise TimeoutError()
        self.kv.update.side_effect=lost_ack
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        await self.restart_owner()
        query=await self.query(raw)
        result=await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('committed',23))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)

    async def test_restart_recovers_published_fence_without_another_card_publication(self):
        async def unavailable(*args,**kwargs):raise TimeoutError()
        actual=self.kv.update.side_effect
        self.kv.update.side_effect=unavailable
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.kv.update.side_effect=actual
        query=await self.query(raw)
        with patch.object(self.owner,'_settle',side_effect=RuntimeError('PRIVATE journal unavailable')):
            with self.assertRaises(RuntimeError):
                await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertIn('_agentmuxRecoveryFence',strict_loads(self.entry.value))
        await self.restart_owner()
        result=await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('rejected',23))
        self.assertEqual(self.kv.update.await_count,2)
        self.assertEqual(strict_loads(self.entry.value)['comments'],[])

    async def test_recovery_refuses_fence_that_would_exceed_the_card_limit(self):
        async def unavailable(*args,**kwargs):raise TimeoutError()
        self.kv.update.side_effect=unavailable
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        import json
        card=strict_loads(self.entry.value)
        card['padding']=''
        overhead=len(json.dumps(card).encode())
        card['padding']='x'*(45000-overhead)
        self.entry.value=json.dumps(card).encode()
        self.assertEqual(len(self.entry.value),45000)
        query=await self.query(raw)
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.entry.value),45000)

    async def changed_cancellation_write(self):
        actual=self.service.ingress.admit
        async def changed(raw,*,cancellation_ref):
            return await actual(raw,cancellation_ref=ref('different-cancel'))
        with patch.object(self.service.ingress,'admit',side_effect=changed):
            return await self.write()

    async def test_finished_replay_refuses_changed_original_operation_metadata(self):
        raw=await self.write()
        await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        changed=await self.changed_cancellation_write()
        with self.assertRaisesRegex(ContractError,'owner_operation_conflict'):
            await self.owner.apply(changed,service_request_bytes=self.wrapper(changed))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.journal_js.messages),4)

    async def test_pending_replay_refuses_changed_original_operation_metadata(self):
        async def unavailable(*args,**kwargs):raise TimeoutError()
        self.kv.update.side_effect=unavailable
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        changed=await self.changed_cancellation_write()
        with self.assertRaisesRegex(ContractError,'owner_operation_conflict'):
            await self.owner.apply(changed,service_request_bytes=self.wrapper(changed))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.journal_js.messages),2)

    async def test_joined_recovery_checks_resource_after_final_authorization(self):
        raw=await self.write()
        result=await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        operation=strict_loads(raw)['operation']
        async def completed():return result
        worker=asyncio.create_task(completed())
        await worker
        self.owner._originals[(operation['operationId'],operation['payloadDigest'])]=(strict_loads(raw),worker)
        authorize=self.owner._authorize_recovery
        calls=0
        async def withdrawn(*args,**kwargs):
            nonlocal calls
            envelope=await authorize(*args,**kwargs)
            calls+=1
            if calls==2:self.legacy.owner.js=object()
            return envelope
        query=await self.query(raw)
        with patch.object(self.owner,'_authorize_recovery',side_effect=withdrawn):
            with self.assertRaisesRegex(ContractError,'capability_resource_stale'):
                await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual(calls,2)

    async def test_actual_native_write_uses_common_storage_receipt_and_domain_rules(self):
        raw=await self.write()
        result=await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.assertEqual((result['outcome'],result['resourceRef']['revision'],result['receiptRef']['revision']),
                         ('applied',23,4))
        self.assertEqual([c['text'] for c in strict_loads(self.entry.value)['comments']],['one'])
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)

    async def test_reconcile_uses_common_storage_outcome_with_separate_card_reference(self):
        raw=await self.write()
        receipt=await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        validate('capability-storage-write-reply',receipt)
        query=await self.query(raw)
        result=await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        validate('capability-outcome-query-reply',result)
        self.assertEqual(result,{'operationId':strict_loads(raw)['operation']['operationId'],
            'payloadDigest':strict_loads(raw)['operation']['payloadDigest'],
            'contractId':'capability-storage-write','recordRef':receipt['receiptRef'],
            'resourceRef':receipt['resourceRef'],'outcome':'committed'})
        self.assertEqual((result['recordRef']['revision'],result['resourceRef']['revision']),(4,23))

    async def test_reconcile_absence_does_not_dispatch_an_unseen_write(self):
        raw=await self.write()
        query=await self.query(raw)
        result=await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['recordRef'],result['resourceRef']),('absent',None,None))
        self.assertEqual(self.journal_js.messages,[])
        self.kv.update.assert_not_awaited()

    async def test_reconcile_stale_write_uses_retained_rejection_and_observed_card_reference(self):
        raw=await self.write(expected=6)
        receipt=await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        query=await self.query(raw)
        result=await self.owner.reconcile(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['recordRef'],result['resourceRef']),
                         ('rejected',receipt['receiptRef'],receipt['resourceRef']))
        self.assertEqual((result['recordRef']['revision'],result['resourceRef']['revision']),(3,7))
        self.kv.update.assert_not_awaited()

    async def test_lost_ack_recovers_original_card_revision_without_another_comment(self):
        actual=self.kv.update.side_effect
        async def lost_ack(*args,**kwargs):
            await actual(*args,**kwargs)
            raise TimeoutError('PRIVATE acknowledgment detail')
        self.kv.update.side_effect=lost_ack
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        query=await self.query(raw)
        result=await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('applied',23))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual([c['text'] for c in strict_loads(self.entry.value)['comments']],['one'])
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(await self.owner.recover(query,service_request_bytes=self.wrapper(query)),result)

    async def test_recovery_fences_unconfirmed_noncommit_without_reapplying_comment(self):
        actual=self.kv.update.side_effect
        calls=0
        async def unavailable_once(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==1:raise TimeoutError('PRIVATE publication detail')
            return await actual(*args,**kwargs)
        self.kv.update.side_effect=unavailable_once
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        query=await self.query(raw)
        result=await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual(result['outcome'],'rejected')
        self.assertEqual(strict_loads(self.entry.value)['comments'],[])
        self.assertIn('_agentmuxRecoveryFence',strict_loads(self.entry.value))
        self.assertEqual(self.kv.update.await_count,2)
        self.assertEqual(self.legacy.store.q('SELECT * FROM fed_audit'),[])

    async def test_missing_card_stays_uncertain_and_never_recreates_or_reapplies(self):
        async def unknown(*args,**kwargs):raise TimeoutError()
        self.kv.update.side_effect=unknown
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        from nats.js.errors import KeyDeletedError
        self.kv.get.side_effect=KeyDeletedError()
        query=await self.query(raw)
        for _ in range(2):
            with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
                await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.journal_js.messages),3)

    async def test_stale_native_revision_returns_conflict_without_card_metadata_write(self):
        raw=await self.write(expected=6)
        before=self.entry.value
        result=await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.assertEqual((result['outcome'],result['resourceRef']['revision'],result['receiptRef']['revision']),
                         ('conflict',7,3))
        self.assertEqual(self.entry.value,before)
        self.kv.update.assert_not_awaited()
        self.assertEqual(self.legacy.store.q('SELECT * FROM fed_audit'),[])

    async def test_parent_revocation_after_owner_dispatch_claim_prevents_card_cas(self):
        raw=await self.write()
        phase=self.owner._phase
        async def withdrawn(contract,*args,**kwargs):
            stored=await phase(contract,*args,**kwargs)
            if contract=='federation-board-dispatch':
                parent=copy.deepcopy(self.parent);previous=copy.deepcopy(parent['ref'])
                parent['ref']['revision']+=1;parent['status']='revoked'
                await self.set_row(parent,previous)
            return stored
        with patch.object(self.owner,'_phase',side_effect=withdrawn):
            with self.assertRaises(ContractError):
                await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.kv.update.assert_not_awaited()
        self.assertEqual(len(self.journal_js.messages),2)

    async def test_cancelled_reply_and_close_join_the_original_card_worker(self):
        actual=self.kv.update.side_effect
        started,release=asyncio.Event(),asyncio.Event()
        async def blocked(*args,**kwargs):
            started.set();await release.wait()
            return await actual(*args,**kwargs)
        self.kv.update.side_effect=blocked
        raw=await self.write()
        reply=asyncio.create_task(self.owner.apply(raw,service_request_bytes=self.wrapper(raw)))
        await started.wait()
        reply.cancel()
        with self.assertRaises(asyncio.CancelledError):await reply
        try:
            with self.assertRaisesRegex(ContractError,'board_owner_cleanup_incomplete'):
                await self.owner.close(timeout=.001)
        finally:
            release.set()
        await self.owner.close(timeout=5)
        operation=strict_loads(raw)['operation']
        result=await self.journal.outcome(operation['operationId'],operation['payloadDigest'])
        self.assertEqual((result.phase,result.result),('finished','applied'))
        self.assertEqual(self.kv.update.await_count,1)
        self.assertEqual(len(self.owner._workers),0)

    async def test_audit_and_projection_recovery_does_not_duplicate_audit(self):
        raw=await self.write()
        actual=self.legacy.owner.db
        mirror=self.resource.board._operations._mirror
        failed=False
        async def unavailable(fn,*args,**kwargs):
            nonlocal failed
            if fn==mirror and not failed:
                failed=True
                raise RuntimeError('PRIVATE projection failure')
            return await actual(fn,*args,**kwargs)
        self.legacy.owner.db=unavailable
        with self.assertRaises(RuntimeError):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.legacy.store.q('SELECT * FROM p_board_cards'),[])
        query=await self.query(raw)
        result=await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual(result['outcome'],'applied')
        self.assertEqual(len(self.legacy.store.q('SELECT * FROM fed_audit')),1)
        self.assertEqual(self.legacy.store.q1('SELECT rev FROM p_board_cards')['rev'],23)
        self.assertEqual(self.kv.update.await_count,1)

    async def test_fresh_query_recovers_after_original_deadline_without_reauthorizing_it(self):
        actual=self.kv.update.side_effect
        async def lost_ack(*args,**kwargs):
            await actual(*args,**kwargs)
            raise TimeoutError()
        self.kv.update.side_effect=lost_ack
        raw=await self.write()
        with self.assertRaisesRegex(ContractError,'board_outcome_uncertain'):
            await self.owner.apply(raw,service_request_bytes=self.wrapper(raw))
        self.now=NOW+timedelta(seconds=40)
        self.assertLess(datetime.fromisoformat(strict_loads(raw)['operation']['deadline']),self.now)
        later=self.now
        class LaterClock(native_tests.journal_tests.service_tests._Clock):
            @classmethod
            def now(cls,tz=None):return later
        with patch('identity.authority._utc_now',return_value=later):
            with patch('identity.ingress.datetime',LaterClock),patch('state_owner.ledger.datetime',LaterClock), \
                 patch('capability_owner.board_journal.datetime',LaterClock), \
                 patch('capability_owner.board_phase_signer.datetime',LaterClock), \
                 patch('capability_owner.board_owner.datetime',LaterClock):
                self.claims.update(issuedAt=later.isoformat().replace('+00:00','Z'),
                    expiresAt=(later+timedelta(seconds=30)).isoformat().replace('+00:00','Z'))
                query=await self.query(raw)
                result=await self.owner.recover(query,service_request_bytes=self.wrapper(query))
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('applied',23))
        self.assertEqual(self.kv.update.await_count,1)
