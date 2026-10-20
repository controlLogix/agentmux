"""Retained original execution with real authority and credential custody."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.ingress import EnrolledIngress
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED
from .test_task_credentials import TaskCredentialTests
from .retained import RetainedExecutionOwner, ExecutionServiceSigner, SERVICE_COMMANDS


class RetainedExecutionTests(TaskCredentialTests):
    async def retained_owner(self):
        await self.reserve()
        now=datetime.now(timezone.utc)
        self.plan.update(issuedAt=(now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
            expiresAt=(now+timedelta(seconds=60)).isoformat().replace('+00:00','Z'))
        await self.enroll()
        self.original_start=self.start()
        admission=await self.plans.admit_start(self.original_start,task_inspection=self.inspection())
        self.run=strict_loads(admission.binding)
        binding=OwnerBinding('hub-one','execution',self.run['runRef']['id'],'attempt',canonical_bytes(self.scope))
        self.execution_js=FakeJetStream(self.policy);self.execution_js.config.subjects=[owner_subject(binding)]
        self.execution_ledger=OwnerLedger(self.execution_js,stream='OWNER',subject=owner_subject(binding),binding=binding,
            retention=self.policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        template=next(g for g in self.record['state']['grants'] if g['ref']==ref('task-credential-observe-grant'))
        for contract in ('execution-run-record','execution-run-observe'):
            self.record['state']['grants'].append({**copy.deepcopy(template),'ref':ref(contract+'-grant'),
                'contractId':contract,'resourceId':self.run['runRef']['id']})
        self.record['state']['grants'].append({**copy.deepcopy(template),'ref':ref('capability-process-cancel-grant'),
            'contractId':'capability-process-cancel','resourceId':'executor','actorRef':ref('human'),'callerRef':ref('human')})
        self.sync()
        ingress=EnrolledIngress(self.service.reader,issuer_ref=ref('issuer'),signing_seed=SEED)
        self.signer=ExecutionServiceSigner(ingress,owner_identity_ref=ref('administrator'),
            transport_ref=ref('administrator-transport'),grants={name:ref(name+'-grant') if name!='identity-application-account-resolve'
                else ref('account-resolve-grant') for name in SERVICE_COMMANDS},signing_seed=bytes(reversed(SEED)),
            account_payload=self.account_payload,task_read_grant_ref=ref('worker-read-grant'),task_approval_refs=[])
        self.execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.addAsyncCleanup(self.execution.close)
        return self.execution

    async def observe_command(self):
        return await self.signer.observe(self.run,len(self.execution_js.messages))

    def cancel_command(self,operation='original-cancel'):
        return self.request('capability-process-cancel',{'resourceRef':ref('executor'),'input':{'runRef':self.run['runRef']}},
            caller='human',expected=1,operation=operation)

    async def test_first_original_retained_before_credentials_and_replay_conflict(self):
        execution=await self.retained_owner()
        result=strict_loads(await execution.start(self.original_start,task_inspection=self.inspection()))
        self.assertEqual(result['step'],'pending-enrollment')
        self.assertEqual(len(self.execution_js.messages),2)
        first=strict_loads(self.execution_js.messages[0].data)
        self.assertEqual(first['operation'],self.run['originalOperation'])
        self.assertEqual(first['operation']['expectedVersion'],1)
        self.assertEqual(first['previousRevision'],0)
        self.assertEqual(first['state']['originalEnvelope'],strict_loads(self.original_start))
        self.assertEqual(self.commands,[])
        self.assertEqual(strict_loads(await execution.start(self.original_start,task_inspection=self.inspection())),result)
        self.assertEqual(len(self.execution_js.messages),2)
        changed=strict_loads(self.original_start);changed['operation']['expectedVersion']=2
        with self.assertRaisesRegex(ContractError,'execution_original_conflict'):
            await execution.start(canonical_bytes(changed),task_inspection=self.inspection())
        enrollment=strict_loads(await execution.enrollment(await self.observe_command()))
        self.assertIn('enrollment',enrollment)
        self.assertNotIn(enrollment['record']['transportRef'],[row['ref'] for row in self.record['state']['transports']])

    async def test_lost_prepare_observer_retains_original_task_and_no_second_effect(self):
        execution=await self.retained_owner();entered=asyncio.Event();release=asyncio.Event()
        original=self.credentials.prepare
        async def held(*args,**kwargs):
            entered.set();await release.wait();return await original(*args,**kwargs)
        self.credentials.prepare=held
        task=asyncio.create_task(execution.start(self.original_start,task_inspection=self.inspection()))
        waiter=asyncio.create_task(entered.wait())
        done,_=await asyncio.wait((task,waiter),timeout=10,return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            waiter.cancel();await asyncio.gather(waiter,return_exceptions=True)
            await task
        if waiter not in done:
            release.set();await task
            self.fail('Original did not reach credential preparation')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(len(execution._jobs),1)
        self.assertEqual(len(self.execution_js.messages),1)
        release.set();await asyncio.gather(*execution._jobs)
        self.assertEqual(len(self.credential_js.messages),1)
        self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['step'],'pending-enrollment')
        self.assertEqual(len(self.execution_js.messages),2)

    async def test_cancel_before_dispatch_is_terminal_and_retires_prepared_generation(self):
        execution=await self.retained_owner()
        await execution.start(self.original_start,task_inspection=self.inspection())
        result=strict_loads(await execution.cancel(self.cancel_command()))
        self.assertEqual(result['status'],'terminal')
        self.assertEqual(self.commands,[])
        await execution.retire(await self.observe_command())
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'retired')
        self.assertEqual(self.commands,[])
        self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['step'],'retired')

    async def test_lost_prepare_reply_still_retires_original_without_enrollment_result(self):
        execution=await self.retained_owner();original=self.credentials.prepare
        async def lost(*args,**kwargs):
            await original(*args,**kwargs)
            raise ContractError('lost_prepare_reply')
        self.credentials.prepare=lost
        with self.assertRaisesRegex(ContractError,'lost_prepare_reply'):
            await execution.start(self.original_start,task_inspection=self.inspection())
        self.assertEqual(len(self.credential_js.messages),1)
        self.assertIsNone(strict_loads(self.execution_js.messages[0].data)['state']['enrollment'])
        await execution.cancel(self.cancel_command())
        await execution.retire(await self.observe_command())
        history=self.credentials._history(await self.credential_ledger.current())
        self.assertEqual(history['phase'],'retired')
        self.assertEqual(history['record']['prepareOperationId'],
            strict_loads(self.execution_js.messages[0].data)['state']['credentialPrepare']['operation']['operationId'])
        self.assertEqual(self.commands,[])

    async def test_close_timeout_can_retry_after_same_original_job_joins(self):
        execution=await self.retained_owner();entered=asyncio.Event();release=asyncio.Event()
        original=self.credentials.prepare
        async def held(*args,**kwargs):
            entered.set();await release.wait();return await original(*args,**kwargs)
        self.credentials.prepare=held
        operation=asyncio.create_task(execution.start(self.original_start,task_inspection=self.inspection()))
        waiter=asyncio.create_task(entered.wait())
        done,_=await asyncio.wait((operation,waiter),timeout=10,return_when=asyncio.FIRST_COMPLETED)
        if operation in done:
            waiter.cancel();await asyncio.gather(waiter,return_exceptions=True);await operation
        try:
            self.assertIn(waiter,done)
            with self.assertRaisesRegex(ContractError,'execution_users_not_joined'):await execution.close(timeout=0.01)
            failed=execution._closing
        finally:release.set()
        await operation
        await execution.close()
        self.assertIsNot(failed,execution._closing)
        self.assertTrue(self.adapter._checkpointed)
        self.assertFalse(execution._jobs)

    async def created_pending(self):
        from identity.transitions import transition
        execution=await self.retained_owner()
        await execution.start(self.original_start,task_inspection=self.inspection())
        enrollment=strict_loads(await execution.enrollment(await self.observe_command()))
        self.record['state']=transition(self.record['state'],'identity-enroll',enrollment['enrollment'],hub_id='hub-one');self.sync()
        async def lost(args,**kwargs):
            if args[0]=='stop' and self.observed['State']['Status']=='created':
                self.commands.append('stop');return b''
            result=await self.command(args,**kwargs)
            if args[0]=='create':raise ContractError('lost_create_reply')
            return result
        self.engine._run=AsyncMock(side_effect=lost)
        with self.assertRaisesRegex(ContractError,'lost_create_reply'):
            await execution.dispatch(self.original_start,task_inspection=self.inspection())
        self.assertEqual(self.commands.count('create'),1)
        self.assertEqual(self.commands.count('start'),0)
        self.assertIsNone(next(iter(self.adapter._runs.values()))['id'])
        self.assertEqual(self.observed['State'],{'Status':'created','Running':False,'ExitCode':0,'Pid':0})
        first=copy.deepcopy(strict_loads(self.execution_js.messages[0].data))
        result=strict_loads(await execution.cancel(self.cancel_command()))
        self.assertEqual(result['status'],'cancel-intent')
        return execution,first

    async def test_actual_create_reply_loss_retires_exact_never_started(self):
        execution,first=await self.created_pending()
        result=strict_loads(await execution.retire(await self.observe_command()))
        self.assertEqual(result['status'],'terminal')
        self.assertEqual(result['step'],'retired')
        self.assertEqual(self.commands.count('create'),1)
        self.assertEqual(self.commands.count('start'),0)
        self.assertEqual(self.commands.count('rm'),1)
        self.assertEqual(strict_loads(self.execution_js.messages[0].data),first)
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'retired')
        self.assertIsNone(self.observed)

    async def test_created_retirement_refuses_pending_running(self):
        execution,_=await self.created_pending()
        self.observed['State'].update(Status='running',Running=True,Pid=123)
        with self.assertRaisesRegex(ContractError,'execution_cleanup_running'):
            await execution.retire(await self.observe_command())
        self.assertEqual(self.observed['State']['Status'],'running')
        self.assertNotIn('rm',self.commands)
        self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['status'],'cancel-intent')

    async def test_created_retirement_refuses_absence_as_unknown(self):
        execution,_=await self.created_pending();self.observed=None
        with self.assertRaisesRegex(ContractError,'execution_physical_state_unresolved'):
            await execution.retire(await self.observe_command())
        self.assertNotIn('rm',self.commands)
        self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['status'],'cancel-intent')

    async def test_created_retirement_refuses_substituted_resource(self):
        execution,_=await self.created_pending();original=copy.deepcopy(self.observed)
        self.observed=copy.deepcopy(self.observed)
        self.observed['Config']['Labels']['agentmux.task.binding']='sha256:'+'0'*64
        try:
            with self.assertRaisesRegex(ContractError,'execution_physical_state_unresolved'):
                await execution.retire(await self.observe_command())
            self.assertNotIn('rm',self.commands)
            self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['status'],'cancel-intent')
        finally:self.observed=original

    async def test_created_retirement_joins_private_users_before_cleanup(self):
        from hub.nats_transport import new_client
        execution,_=await self.created_pending();client=new_client();self.credentials._clients.append(client)
        try:
            with self.assertRaisesRegex(ContractError,'task_credential_users_not_joined'):
                await execution.retire(await self.observe_command())
            self.assertNotIn('rm',self.commands)
            self.assertEqual(self.observed['State']['Status'],'created')
        finally:
            await client.close();self.credentials._clients.remove(client)
        await execution.retire(await self.observe_command())
        self.assertEqual(self.commands.count('rm'),1)

    async def prepared_supervisor(self):
        from identity.transitions import transition
        execution=await self.retained_owner()
        await execution.start(self.original_start,task_inspection=self.inspection())
        enrollment=strict_loads(await execution.enrollment(await self.observe_command()))
        self.record['state']=transition(self.record['state'],'identity-enroll',enrollment['enrollment'],hub_id='hub-one');self.sync()
        prepare=self.adapter.prepare
        async def stop_before_delivery(*args,**kwargs):
            await prepare(*args,**kwargs)
            raise ContractError('prepared_supervisor_checkpoint')
        self.adapter.prepare=stop_before_delivery
        try:
            with self.assertRaisesRegex(ContractError,'prepared_supervisor_checkpoint'):
                await execution.dispatch(self.original_start,task_inspection=self.inspection())
        finally:self.adapter.prepare=prepare
        self.assertTrue(self.observed['State']['Running'])
        return execution

    async def admitted_stop_revocation(self,*,native):
        execution=await self.prepared_supervisor()
        active=True;checks=[]
        async def terminal(session_id,actor,scope):
            checks.append((session_id,actor,scope))
            if not active:raise ContractError('oidc_terminal_session_inactive')
        if native:
            self.plans._ingress.require_terminal_sessions(terminal)
            raw=self.request('capability-process-cancel',{'resourceRef':ref('executor'),'input':{'runRef':self.run['runRef']}},
                caller='human',expected=1,operation='native-cancel',terminalSessionId='terminal-cancel')
        else:raw=self.cancel_command()
        entered=asyncio.Event();release=asyncio.Event();find=self.engine.find;reads=0
        async def held(name):
            nonlocal reads
            reads+=1
            # First read is D's observation. Second is B's exact original stop,
            # after D admitted the current cancel and handed off its ownership.
            if reads==2:entered.set();await release.wait()
            return await find(name)
        self.engine.find=AsyncMock(side_effect=held)
        first=self.execution_js.messages[0].data
        original=asyncio.create_task(execution.cancel(raw));waiter=asyncio.create_task(entered.wait())
        try:
            done,_=await asyncio.wait((original,waiter),timeout=10,return_when=asyncio.FIRST_COMPLETED)
            if original in done:await original
            self.assertIn(waiter,done)
            self.assertEqual(self.commands.count('stop'),0)
            if native:
                self.assertTrue(checks)
                self.assertTrue(all(item==('terminal-cancel',ref('human'),self.scope) for item in checks))
                active=False
            else:
                grant=next(item for item in self.record['state']['grants'] if item['ref']==ref('capability-process-cancel-grant'))
                grant['status']='revoked';self.sync()
            release.set()
            with self.assertRaisesRegex(ContractError,'oidc_terminal_session_inactive' if native else 'execution_not_authorized'):
                await original
            self.assertEqual(self.commands.count('stop'),1)
            self.assertFalse(self.observed['State']['Running'])
            self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['status'],'terminal')
            with self.assertRaises(ContractError):await execution.cancel(raw)
            self.assertEqual(self.commands.count('stop'),1)
            self.assertEqual(self.execution_js.messages[0].data,first)
            self.assertEqual(strict_loads((await self.owner._ledger.current()).latest.record)['state']['status'],'reserved')
            await execution.retire(await self.observe_command())
            self.assertEqual(self.commands.count('create'),1)
            self.assertEqual(self.commands.count('rm'),1)
        finally:
            release.set();waiter.cancel()
            await asyncio.gather(original,waiter,return_exceptions=True)
            self.engine.find=find

    async def test_admitted_stop_retains_truth_after_current_cancel_grant_revoked(self):
        await self.admitted_stop_revocation(native=False)

    async def test_admitted_stop_retains_truth_after_native_session_refused(self):
        await self.admitted_stop_revocation(native=True)

    async def test_start_observer_timeout_keeps_same_original_and_first_bound(self):
        execution=await self.retained_owner();entered=asyncio.Event();release=asyncio.Event()
        prepare=self.credentials.prepare;calls=[]
        async def held(*args,**kwargs):
            calls.append(1);entered.set();await release.wait();return await prepare(*args,**kwargs)
        self.credentials.prepare=held
        async def observer():
            async with asyncio.timeout(1):
                return await execution.start(self.original_start,task_inspection=self.inspection())
        original_observer=asyncio.create_task(observer());waiter=asyncio.create_task(entered.wait())
        try:
            done,_=await asyncio.wait((original_observer,waiter),timeout=10,return_when=asyncio.FIRST_COMPLETED)
            if original_observer in done:await original_observer
            self.assertIn(waiter,done)
            first=self.execution_js.messages[0].data
            owned=tuple(execution._jobs);self.assertEqual(len(owned),1)
            with self.assertRaises(TimeoutError):await original_observer
            self.assertEqual(tuple(execution._jobs),owned)
            self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['step'],'credential-prepare-intent')
            release.set();await asyncio.gather(*owned)
            self.assertEqual(calls,[1])
            self.assertEqual(self.execution_js.messages[0].data,first)
            self.assertEqual(len(self.credential_js.messages),1)
            self.assertEqual(strict_loads(await execution.query(await self.observe_command()))['step'],'pending-enrollment')
            self.assertEqual(self.commands,[])
        finally:
            release.set();waiter.cancel()
            await asyncio.gather(original_observer,waiter,*tuple(execution._jobs),return_exceptions=True)


for _name in dir(TaskCredentialTests):
    if _name.startswith('test_') and _name not in vars(RetainedExecutionTests):setattr(RetainedExecutionTests,_name,None)
