"""Composed D owner on native ARM64 with real retained storage and task proof."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.ingress import EnrolledIngress
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from .container import TaskContainerAdapter
from .network import SelectedNetwork
from .retained import RetainedExecutionOwner, ExecutionServiceSigner, SERVICE_COMMANDS
from .test_task_credentials_live import NativeTaskCredentialTests


class NativeRetainedExecutionTests(NativeTaskCredentialTests):
    def make_credentials(self):
        # Install these fixture grants before the authority moves to the real
        # retained stream. This does not alter production authority or grant it.
        identity={'format':'agentmux-execution-run-reference-v1','ownerHubId':'hub-one',
            'scope':self.scope,'executorId':'executor','operationId':'original-start'}
        run_id='execution-'+payload_digest(identity).split(':',1)[1]
        grants=self.record['state']['grants'];known={g['ref']['id'] for g in grants}
        template=next(g for g in grants if g['ref']==ref('task-credential-observe-grant'))
        for contract in ('execution-run-record','execution-run-observe','capability-process-cancel'):
            if contract+'-grant' in known:continue
            human=contract=='capability-process-cancel'
            grants.append({**copy.deepcopy(template),'ref':ref(contract+'-grant'),'contractId':contract,
                'resourceId':'executor' if human else run_id,
                'actorRef':ref('human' if human else 'administrator'),'callerRef':ref('human' if human else 'administrator')})
        self.sync()
        return super().make_credentials()

    async def native_owner(self):
        await self.credentials.close()
        script=b"from pathlib import Path\nimport time\nPath('/workspace/started').write_text('approved')\ntime.sleep(25)\n"
        (Path(self.host._path)/'file').write_bytes(script)
        self.profile['recipe']['sha256']='sha256:'+hashlib.sha256(script).hexdigest()
        self.plans=self.make_owner();self.addAsyncCleanup(self.plans.close)
        self.adapter=TaskContainerAdapter(self.plans,self.real_engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.live_adapter=self.adapter;self.addAsyncCleanup(self.adapter.close)
        self.credentials=self.make_credentials()
        await self.reserve()
        now=datetime.now(timezone.utc)
        self.plan.update(issuedAt=(now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
            expiresAt=(now+timedelta(seconds=60)).isoformat().replace('+00:00','Z'))
        await self.enroll()
        self.original_start=self.start()
        admission=await self.plans.admit_start(self.original_start,task_inspection=self.inspection())
        self.run=strict_loads(admission.binding)
        binding=OwnerBinding('hub-one','execution',self.run['runRef']['id'],'attempt',canonical_bytes(self.scope))
        info=await self.admin.jetstream().add_stream(self.policy.stream_config(stream='EXECUTION',subject=owner_subject(binding)))
        self.execution_ledger=OwnerLedger(self.admin.jetstream(),stream='EXECUTION',subject=owner_subject(binding),binding=binding,
            retention=self.policy,stream_identity=StreamIdentity(info.created,0),require_completion_budget=True)
        ingress=EnrolledIngress(self.service.reader,issuer_ref=ref('issuer'),signing_seed=SEED)
        self.signer=ExecutionServiceSigner(ingress,owner_identity_ref=ref('administrator'),transport_ref=ref('administrator-transport'),
            grants={name:ref(name+'-grant') if name!='identity-application-account-resolve' else ref('account-resolve-grant')
                for name in SERVICE_COMMANDS},signing_seed=bytes(reversed(SEED)),account_payload=self.account_payload,
            task_read_grant_ref=ref('worker-read-grant'),task_approval_refs=[])
        self.execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.addAsyncCleanup(self.execution.close)
        return self.execution

    async def native_observe(self):
        return await self.signer.observe(self.run,(await self.execution_ledger.current()).sequence)

    def native_cancel(self):
        return self.request('capability-process-cancel',{'resourceRef':ref('executor'),'input':{'runRef':self.run['runRef']}},
            caller='human',expected=1,operation='original-cancel')

    async def test_native_composed_original_execution_and_cancel(self):
        execution=await self.native_owner()
        result=strict_loads(await execution.start(self.original_start,task_inspection=self.inspection()))
        self.assertEqual(result['step'],'pending-enrollment')
        enrollment=strict_loads(await execution.enrollment(await self.native_observe()))
        self.assertFalse(self.adapter._runs)
        # The existing organization administrator performs the actual enrollment.
        await self.admin_change('identity-enroll',enrollment['enrollment'])
        result=strict_loads(await execution.dispatch(self.original_start,task_inspection=self.inspection()))
        self.assertEqual(result['status'],'running')
        marker=Path(self.host._path)/'started'
        end=datetime.fromisoformat(self.run['executionValidUntil'])
        while not marker.exists() and datetime.now(timezone.utc)<end:
            await asyncio.sleep(0.01)
        self.assertEqual(marker.read_text(),'approved')
        first=await self.execution_ledger.current()
        self.assertEqual(first.sequence,10)
        self.assertEqual(strict_loads(first.records[0].record)['operation'],self.run['originalOperation'])
        self.assertFalse(self.credentials._clients or self.credentials._subscriptions or self.credentials._handlers or self.credentials._proofs)
        replay=strict_loads(await execution.start(self.original_start,task_inspection=self.inspection()))
        self.assertEqual(replay,result)
        result=strict_loads(await execution.cancel(self.native_cancel()))
        self.assertEqual(result['status'],'terminal')
        await self.admin_change('identity-revoke',{'authorityId':'authority-one','targetRef':enrollment['record']['transportRef']})
        await execution.retire(await self.native_observe())
        final=await self.execution_ledger.current()
        self.assertEqual(strict_loads(final.latest.record)['state']['step'],'retired')
        self.assertEqual(strict_loads(final.records[0].record)['state']['originalEnvelope'],strict_loads(self.original_start))
        self.assertFalse(self.real_engine._jobs)
        name=next(iter(self.adapter._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))

    async def test_native_lost_create_restart_expired_original_uses_same_resource(self):
        execution=await self.native_owner()
        await execution.start(self.original_start,task_inspection=self.inspection())
        enrollment=strict_loads(await execution.enrollment(await self.native_observe()))
        await self.admin_change('identity-enroll',enrollment['enrollment'])
        calls=[];run_command=self.real_engine._run
        async def counted(args,**kwargs):
            calls.append(args[0])
            result=await run_command(args,**kwargs)
            if args[0]=='create':raise ContractError('lost_create_reply')
            return result
        self.real_engine._run=counted
        with self.assertRaisesRegex(ContractError,'lost_create_reply'):
            await execution.dispatch(self.original_start,task_inspection=self.inspection())
        snapshot=await self.execution_ledger.current()
        original_state=strict_loads(snapshot.latest.record)['state']
        self.assertEqual(original_state['step'],'container-create-intent')
        self.assertIsNone(original_state['resourceRef'])
        self.assertIsNone(next(iter(self.adapter._runs.values()))['id'])
        original_name=next(iter(self.adapter._runs.values()))['spec']['name']
        physical=await self.real_engine.find(original_name)
        original_container=physical['Id']
        self.assertEqual(physical['State']['Status'],'created')
        self.assertFalse(physical['State']['Running'])
        self.assertEqual(physical['State']['Pid'],0)
        await execution.close()
        self.assertTrue(self.adapter._checkpointed)
        self.adapter=TaskContainerAdapter(self.plans,self.real_engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.live_adapter=self.adapter;self.addAsyncCleanup(self.adapter.close)
        self.credentials=self.make_credentials()
        self.execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.addAsyncCleanup(self.execution.close)
        end=datetime.fromisoformat(original_state['admissionEnd'])
        await asyncio.sleep(max(0,(end-datetime.now(timezone.utc)).total_seconds())+0.1)
        result=strict_loads(await self.execution.reconcile(await self.native_observe()))
        self.assertIn(result['status'],('terminal','unknown'))
        recovered=next(iter(self.adapter._runs.values()))
        self.assertEqual(recovered['id'],original_container)
        self.assertEqual(recovered['spec']['name'],original_name)
        result=strict_loads(await self.execution.cancel(self.native_cancel()))
        self.assertEqual(result['status'],'cancel-intent')
        await self.admin_change('identity-revoke',{'authorityId':'authority-one','targetRef':enrollment['record']['transportRef']})
        await self.execution.retire(await self.native_observe())
        self.assertEqual(calls.count('create'),1)
        self.assertEqual(calls.count('start'),0)
        self.assertEqual(calls.count('rm'),1)
        self.assertFalse(self.real_engine._jobs)
        self.assertIsNone(await self.real_engine.find(original_name))
        final=await self.execution_ledger.current()
        self.assertEqual(strict_loads(final.records[0].record)['state']['originalEnvelope'],strict_loads(self.original_start))
        self.assertEqual(strict_loads(final.latest.record)['state']['executionBinding'],original_state['executionBinding'])

    async def test_native_lost_task_start_and_stop_replies_reconcile_once(self):
        from .container_programs import START, DELIVER
        execution=await self.native_owner()
        await execution.start(self.original_start,task_inspection=self.inspection())
        enrollment=strict_loads(await execution.enrollment(await self.native_observe()))
        await self.admin_change('identity-enroll',enrollment['enrollment'])
        creates=[];original_command=self.real_engine._run
        async def count_create(args,**kwargs):
            if args[0]=='create':creates.append(args[0])
            return await original_command(args,**kwargs)
        self.real_engine._run=count_create
        task_starts=[];private_sends=[];fixed=self.real_engine.exec_fixed
        async def lost_start(container,uid,program,*args,**kwargs):
            if program==DELIVER:private_sends.append(container)
            result=await fixed(container,uid,program,*args,**kwargs)
            if program==START:
                task_starts.append(container)
                raise ContractError('lost_task_start_reply')
            return result
        self.real_engine.exec_fixed=lost_start
        with self.assertRaisesRegex(ContractError,'lost_task_start_reply'):
            await execution.dispatch(self.original_start,task_inspection=self.inspection())
        self.assertEqual(len(task_starts),1)
        marker=Path(self.host._path)/'started'
        end=datetime.fromisoformat(self.run['executionValidUntil'])
        while not marker.exists() and datetime.now(timezone.utc)<end:
            await asyncio.sleep(0.01)
        self.assertEqual(marker.read_text(),'approved')
        result=strict_loads(await execution.reconcile(await self.native_observe()))
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(strict_loads(await execution.dispatch(self.original_start,task_inspection=self.inspection())),result)
        self.assertEqual(len(task_starts),1)
        # Reopen the actual composed owner, including delivered private custody.
        # Digests establish preservation without printing private bytes on failure.
        saved=await self.execution_ledger.current()
        first_record=saved.records[0].record
        state=strict_loads(saved.latest.record)['state'];resource=state['resourceRef']
        credential=self.credentials._history(await self.credential_ledger.current())['record']
        generation=credential['generationRef']
        with self.credentials._store.access(generation) as directory:
            private_digest=hashlib.sha256(self.credentials._store.read(directory,'credential.json')).hexdigest()
            claim_digest=hashlib.sha256(self.credentials._store.read(directory,'delivery.json')).hexdigest()
        name=next(iter(self.adapter._runs.values()))['spec']['name']
        self.assertTrue((await self.real_engine.find(name))['State']['Running'])
        await execution.close()
        self.assertFalse(execution._jobs or self.credentials._clients or self.credentials._subscriptions
            or self.credentials._handlers or self.credentials._proofs or self.real_engine._jobs)
        self.assertTrue((await self.real_engine.find(name))['State']['Running'])
        self.adapter=TaskContainerAdapter(self.plans,self.real_engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.live_adapter=self.adapter;self.addAsyncCleanup(self.adapter.close)
        self.credentials=self.make_credentials()
        execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.execution=execution;self.addAsyncCleanup(execution.close)
        result=strict_loads(await execution.reconcile(await self.native_observe()))
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(next(iter(self.adapter._runs.values()))['id'],resource['containerId'])
        self.assertEqual((await self.execution_ledger.current()).records[0].record,first_record)
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['record'],credential)
        with self.credentials._store.access(generation) as directory:
            self.assertEqual(hashlib.sha256(self.credentials._store.read(directory,'credential.json')).hexdigest(),private_digest)
            self.assertEqual(hashlib.sha256(self.credentials._store.read(directory,'delivery.json')).hexdigest(),claim_digest)
        self.assertEqual(len(creates),1);self.assertEqual(len(private_sends),1);self.assertEqual(len(task_starts),1)
        stop_calls=[];run_command=self.real_engine._run;find=self.real_engine.find;lost_observation=False
        async def lost_stop(args,**kwargs):
            nonlocal lost_observation
            result=await run_command(args,**kwargs)
            if args[0]=='stop':
                stop_calls.append(args[1:]);lost_observation=True
                raise ContractError('lost_stop_reply')
            return result
        async def observe_after_stop(name):
            nonlocal lost_observation
            if lost_observation:
                lost_observation=False
                raise ContractError('lost_stop_observation')
            return await find(name)
        self.real_engine._run=lost_stop;self.real_engine.find=observe_after_stop
        result=strict_loads(await execution.cancel(self.native_cancel()))
        self.assertEqual(result['status'],'cancel-intent')
        self.assertEqual(len(stop_calls),1)
        result=strict_loads(await execution.reconcile(await self.native_observe()))
        self.assertEqual(result['status'],'terminal')
        self.assertEqual(len(stop_calls),1)
        await self.admin_change('identity-revoke',{'authorityId':'authority-one','targetRef':enrollment['record']['transportRef']})
        await execution.retire(await self.native_observe())
        self.assertEqual(len(creates),1);self.assertEqual(len(private_sends),1);self.assertEqual(len(task_starts),1)
        self.assertFalse(self.real_engine._jobs)
        name=next(iter(self.adapter._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))


for _name in dir(NativeTaskCredentialTests):
    if _name.startswith('test_') and _name not in vars(NativeRetainedExecutionTests):setattr(NativeRetainedExecutionTests,_name,None)
