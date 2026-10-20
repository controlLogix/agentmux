"""Actual default native-provider evidence through one composed D dispatch."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.execution_evidence import NativeExecutionEvidence
from identity.ingress import EnrolledIngress
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from capability_owner import test_process_native_delivery as provider_support
from .container import TaskContainerAdapter
from .network import SelectedNetwork
from .retained import RetainedExecutionOwner, ExecutionServiceSigner, SERVICE_COMMANDS
from .test_retained_live import NativeRetainedExecutionTests


class NativeDeliveryExecutionTests(NativeRetainedExecutionTests):
    admin_command=provider_support.ProcessNativeDeliveryTests.admin
    delivery=provider_support.ProcessNativeDeliveryTests.delivery
    install_native_policy=provider_support.ProcessNativeDeliveryTests.install_native_policy

    def make_credentials(self):
        result=super().make_credentials()
        operation='downstream_'+hashlib.sha256(('original-start'+'\0'+'request_'+'c'*64).encode()).hexdigest()
        identity={'format':'agentmux-execution-run-reference-v1','ownerHubId':'hub-one',
            'scope':self.scope,'executorId':'executor','operationId':operation}
        self.install_native_policy('execution-'+payload_digest(identity).split(':',1)[1])
        return result

    async def native_delivery_owner(self):
        await self.credentials.close()
        script=b"from pathlib import Path\nimport time\nPath('/workspace/started').write_text('approved')\ntime.sleep(25)\n"
        (Path(self.host._path)/'file').write_bytes(script)
        self.profile['recipe']['sha256']='sha256:'+hashlib.sha256(script).hexdigest()
        self.plans=self.make_owner();self.addAsyncCleanup(self.plans.close)
        self.adapter=TaskContainerAdapter(self.plans,self.real_engine,self.host,workspace_ref=ref('workspace'),network=SelectedNetwork(ref('network')))
        self.live_adapter=self.adapter;self.addAsyncCleanup(self.adapter.close)
        self.credentials=self.make_credentials()
        await self.reserve();now=datetime.now(timezone.utc)
        self.plan.update(issuedAt=(now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
            expiresAt=(now+timedelta(seconds=60)).isoformat().replace('+00:00','Z'))
        await self.enroll();source=self.start();request_id='request_'+'c'*64
        operation='downstream_'+hashlib.sha256(('original-start'+'\0'+request_id).encode()).hexdigest()
        identity={'format':'agentmux-execution-run-reference-v1','ownerHubId':'hub-one',
            'scope':self.scope,'executorId':'executor','operationId':operation}
        row=self.install_native_policy('execution-'+payload_digest(identity).split(':',1)[1])
        result=await self.admin_command('identity-native-instance-set',{'authorityId':'authority-one','record':row,'previousRef':None})
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')
        authority_ref=ref('authority-one');authority_ref['revision']=(await self.service.reader.current()).sequence
        raw,wrapper=await self.delivery(source,row,authority_ref,request_id)
        evidence=NativeExecutionEvidence(wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')
        admission=await self.plans.admit_start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        self.run=strict_loads(admission.binding)
        binding=OwnerBinding('hub-one','execution',self.run['runRef']['id'],'attempt',canonical_bytes(self.scope))
        info=await self.admin.jetstream().add_stream(self.policy.stream_config(stream='EXECUTION',subject=owner_subject(binding)))
        self.execution_ledger=OwnerLedger(self.admin.jetstream(),stream='EXECUTION',subject=owner_subject(binding),binding=binding,
            retention=self.policy,stream_identity=StreamIdentity(info.created,0),require_completion_budget=True)
        ingress=EnrolledIngress(self.service.reader,issuer_ref=ref('issuer'),signing_seed=SEED)
        self.signer=ExecutionServiceSigner(ingress,owner_identity_ref=ref('administrator'),transport_ref=ref('administrator-transport'),
            grants={name:ref(name+'-grant') if name!='identity-application-account-resolve' else ref('account-resolve-grant') for name in SERVICE_COMMANDS},
            signing_seed=bytes(reversed(SEED)),account_payload=self.account_payload,task_read_grant_ref=ref('worker-read-grant'),task_approval_refs=[])
        self.execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.addAsyncCleanup(self.execution.close)
        return source,row,authority_ref,request_id,raw,wrapper,evidence

    async def test_default_provider_delayed_admin_single_composed_dispatch(self):
        source,row,authority_ref,request_id,raw,wrapper,evidence=await self.native_delivery_owner()
        from .container_programs import START, DELIVER
        effects=[];command=self.real_engine._run;fixed=self.real_engine.exec_fixed
        async def counted_command(args,**kwargs):
            if args[0]=='create':effects.append('create')
            return await command(args,**kwargs)
        async def counted_fixed(container,uid,program,*args,**kwargs):
            if program==DELIVER:effects.append('deliver')
            if program==START:effects.append('start')
            return await fixed(container,uid,program,*args,**kwargs)
        self.real_engine._run=counted_command;self.real_engine.exec_fixed=counted_fixed
        execution=self.execution;public=None
        try:
            try:await execution.start(raw,task_inspection=self.inspection(),native_evidence=evidence)
            except ContractError as exc:
                self.assertEqual(str(exc),'capability_service_expired')
                self.assertEqual(strict_loads(await execution.query(await self.native_observe()))['step'],'pending-enrollment')
            public=strict_loads(await execution.enrollment(await self.native_observe()))
            first=(await self.execution_ledger.current()).records[0].record
            expiry=datetime.fromisoformat(strict_loads(raw)['ingressAttestation']['claims']['expiresAt'])
            self.assertGreater(public['record']['expiresUnix'],expiry.timestamp())
            await asyncio.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+0.1)
            await self.admin_change('identity-enroll',public['enrollment'])
            _,fresh_wrapper=await self.delivery(source,row,authority_ref,request_id)
            current=NativeExecutionEvidence(fresh_wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')
            started=time.monotonic()
            try:
                result=strict_loads(await execution.dispatch(raw,task_inspection=self.inspection(),native_evidence=current))
            except ContractError as exc:
                self.assertEqual(str(exc),'capability_service_expired')
                result=strict_loads(await execution.query(await self.native_observe()))
                print('Expired original delivery withheld; fresh service query recovered owned truth')
            finally:print('Actual default-proof single D dispatch seconds: '+str(round(time.monotonic()-started,3)))
            self.assertEqual(result['status'],'running')
            marker=Path(self.host._path)/'started'
            end=datetime.fromisoformat(self.run['executionValidUntil'])
            while not marker.exists() and datetime.now(timezone.utc)<end:await asyncio.sleep(0.01)
            self.assertEqual(marker.read_text(),'approved')
            self.assertEqual((await self.execution_ledger.current()).records[0].record,first)
            self.assertEqual(self.credentials._history(await self.credential_ledger.current())['record'],public['record'])
            self.assertEqual(effects,['create','deliver','start'])
        finally:
            snapshot=await self.execution_ledger.current()
            if snapshot.latest is not None:
                await execution.cancel(self.native_cancel())
                if public is not None:
                    await self.admin_change('identity-revoke',{'authorityId':'authority-one','targetRef':public['record']['transportRef']})
                await execution.retire(await self.native_observe())
        self.assertFalse(self.real_engine._jobs)
        name=next(iter(self.adapter._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))


for _name in dir(NativeRetainedExecutionTests):
    if _name.startswith('test_') and _name not in vars(NativeDeliveryExecutionTests):setattr(NativeDeliveryExecutionTests,_name,None)
