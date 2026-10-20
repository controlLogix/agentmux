"""Actual signed native Process mapping over the existing execution fixture."""
import copy

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.test_authority import ref, SEED
from .test_process_native_delivery import ProcessNativeDeliveryTests
from .process_admission import ProcessRunAdmission
from .process_resource import ProcessInspectionSigner, ProcessResource
from .receiver import CapabilityReceiver


class ProcessResourceTests(ProcessNativeDeliveryTests):
    def install_native_policy(self,run_id):
        row=super().install_native_policy(run_id)
        template=next(g for g in self.record['state']['grants'] if g['ref']==ref('capability-process-start-grant'))
        self.record['state']['grants'].append({**copy.deepcopy(template),'ref':ref('capability-outcome-query-grant'),
            'contractId':'capability-outcome-query'})
        self.sync()
        facts=row['facts'];facts['grant']['actions']=['start','cancel','reconcile']
        for contract,action in (('capability-process-cancel','cancel'),('capability-outcome-query','reconcile')):
            facts['domainBindings'].append({'id':contract+'-binding','contractId':contract,'action':action,
                'resourceClass':'process','resourceIds':['executor']})
            facts['policy']['decisions'].append({'access':{'action':action,'resourceClass':'process','resourceId':'executor'},'outcome':'allow'})
        return row

    async def resource_case(self):
        case=await self.prepare_native_original(start=False)
        admission=ProcessRunAdmission(self.plans,self.adapter,self.credentials,self.signer,ledger=self.execution_ledger)
        signer=ProcessInspectionSigner(self.signer._ingress,transport_ref=ref('administrator-transport'),
            grant_ref=ref('task-inspect-grant'),signing_seed=bytes(reversed(SEED)))
        resource=ProcessResource(admission,signer,plugin_identity=ref('plugin'),instance_id='plugin-one',package_id='test-plugin')
        receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=(resource,))
        self.resource,self.receiver=resource,receiver
        self.addAsyncCleanup(resource.close);self.addAsyncCleanup(receiver.close)
        return case

    async def packet(self,case,contract,payload,operation):
        source=self.request(contract,payload,caller='human',expected=1,operation=operation)
        if contract=='capability-outcome-query':
            value=strict_loads(source);value['destinationServiceId']='outcome-owner'
            claims=value['ingressAttestation']['claims']
            claims['audience']['serviceId']='outcome-owner'
            value['ingressAttestation']['signature']=sign_claims(claims,SEED)
            source=canonical_bytes(value)
        return await self.delivery(source,case['row'],case['authority_ref'],'request_'+'d'*64,
            binding_id=contract+'-binding')

    async def receive(self,raw,wrapper):
        return strict_loads((await self.receiver.handle(raw,service_request_bytes=wrapper)).payload)

    async def test_start_cancel_and_strict_original_recovery(self):
        case=await self.resource_case()
        result=await self.receive(case['raw'],case['wrapper'])
        self.assertEqual(result,{'receiptRef':self.run['runRef'],'outcome':'accepted'})
        self.assertEqual(self.commands,[])
        first=self.execution_js.messages[0].data
        original=strict_loads(case['raw'])['operation']
        query={'contractId':'capability-process-start','operationId':original['operationId'],'payloadDigest':original['payloadDigest']}
        raw,wrapper=await self.packet(case,'capability-outcome-query',{'resourceRef':ref('executor'),'input':query},'recover-start')
        recovered=await self.receive(raw,wrapper)
        self.assertEqual(set(recovered),{'operationId','payloadDigest','recordRef','outcome'})
        self.assertEqual(recovered['outcome'],'committed')
        self.assertEqual(recovered['recordRef'],self.run['runRef'])
        raw,wrapper=await self.packet(case,'capability-process-cancel',{'resourceRef':ref('executor'),
            'input':{'runRef':self.run['runRef']}},'cancel-run')
        result=await self.receive(raw,wrapper)
        self.assertEqual(result,{'receiptRef':self.run['runRef'],'outcome':'stopped'})
        self.assertEqual(self.execution_js.messages[0].data,first)
        self.assertEqual(self.commands,[])

    async def test_wrong_selected_executor_and_raw_wrapper_refuse_before_owner(self):
        case=await self.resource_case()
        with self.assertRaises(ContractError):await self.receiver.handle(case['raw'])
        self.resource._executor={**ref('executor'),'revision':2}
        with self.assertRaises(ContractError):await self.receive(case['raw'],case['wrapper'])
        self.assertEqual(self.execution_js.messages,[])
        self.assertEqual(self.credential_js.messages,[])
        self.assertEqual(self.commands,[])


for _name in dir(ProcessNativeDeliveryTests):
    if _name.startswith('test_') and _name not in vars(ProcessResourceTests):setattr(ProcessResourceTests,_name,None)
