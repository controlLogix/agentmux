"""Persistent run admission with a controlled stream boundary, not broker proof."""
import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from nats.js.client import JetStreamContext
from nats.js.errors import NotFoundError
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from execution_owner.container import TaskContainerAdapter
from execution_owner.network import SelectedNetwork
from identity.execution_evidence import NativeExecutionEvidence
from identity.test_authority import ref, SEED
from state_owner.test_ledger import FakeJetStream
from .process_admission import ProcessRunAdmission
from .test_process_native_delivery import ProcessNativeDeliveryTests


class RunStreamBoundary(FakeJetStream):
    def __init__(self,policy):
        super().__init__(policy);self.exists=False;self.creates=0;self.lose_create=False

    async def stream_info(self,stream):
        if not self.exists:raise NotFoundError()
        return await super().stream_info(stream)

    async def add_stream(self,config):
        if self.exists:raise RuntimeError('already exists')
        self.config=config;self.exists=True;self.creates+=1
        if self.lose_create:raise TimeoutError('lost create reply')
        return await self.stream_info(config.name)

    async def publish(self,subject,data,*,headers):
        if int(headers['Nats-Expected-Last-Subject-Sequence'])!=len(self.messages):raise RuntimeError('revision conflict')
        self.messages.append(SimpleNamespace(subject=subject,data=data,seq=len(self.messages)+1))
        return SimpleNamespace(stream=self.config.name,seq=len(self.messages),duplicate=False)


class ProcessAdmissionTests(ProcessNativeDeliveryTests):
    async def persistent_case(self):
        case=await self.prepare_native_original(start=False)
        self.inventory_root=self.path/'process-inventory';self.inventory_root.mkdir(mode=0o700)
        self.run_stream=RunStreamBoundary(self.policy)
        self.run_js=object.__new__(JetStreamContext)
        for name in ('stream_info','add_stream','publish','get_msg'):
            setattr(self.run_js,name,AsyncMock(side_effect=getattr(self.run_stream,name)))
        return case,self.admission()

    def admission(self):
        owner=ProcessRunAdmission(self.plans,self.adapter,self.credentials,self.signer,jetstream=self.run_js,
            stream='AMX_PROCESS_TEST',retention=self.policy,inventory_root=self.inventory_root,namespace='test')
        self.addAsyncCleanup(owner.close)
        return owner

    async def restart(self,old):
        await old.close()
        self.adapter=TaskContainerAdapter(self.plans,self.engine,self.host,workspace_ref=ref('workspace'),network=SelectedNetwork(ref('network')))
        self.addAsyncCleanup(self.adapter.close)
        self.credentials=self.make_credentials()
        return self.admission()

    async def fresh(self,case,source=None):
        raw,wrapper=await self.delivery(case['source'] if source is None else source,case['row'],case['authority_ref'],case['request_id'])
        return raw,NativeExecutionEvidence(wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')

    async def start_owned(self,owner,raw,evidence):
        try:await owner.start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        except ContractError as exc:
            self.assertEqual(str(exc),'capability_service_expired')
            snapshot,state=await owner._load()
            result=strict_loads(await owner.query(await self.signer.observe(state['executionBinding'],snapshot.sequence)))
            self.assertEqual(result['step'],'pending-enrollment')

    async def test_interrupted_assignment_reopens_only_same_business_before_first_record(self):
        case,admission=await self.persistent_case()
        match=admission._inventory.match
        def interrupted(name,value):
            result=match(name,value)
            if name=='assignment.json':raise ContractError('interrupted_before_reservation')
            return result
        with patch.object(admission._inventory,'match',side_effect=interrupted):
            with self.assertRaisesRegex(ContractError,'interrupted_before_reservation'):
                await admission.open(case['raw'],task_inspection=self.inspection(),native_evidence=case['evidence'])
        assignment=admission._inventory.read('assignment.json')
        self.assertFalse(self.run_stream.exists)
        restarted=await self.restart(admission)
        self.assertIsNone(await restarted.existing())
        self.assertEqual(self.run_stream.creates,1)
        source=strict_loads(case['source']);op=source['operation']
        op['deadline']=(datetime.fromisoformat(op['deadline'])-timedelta(milliseconds=100)).isoformat().replace('+00:00','Z')
        claims=source['ingressAttestation']['claims'];claims['operation']=copy.deepcopy(op);claims['expiresAt']=op['deadline']
        source['ingressAttestation']['signature']=sign_claims(claims,SEED)
        changed,evidence=await self.fresh(case,canonical_bytes(source))
        with self.assertRaisesRegex(ContractError,'^capability_outcome_conflict$'):
            await restarted.open(changed,task_inspection=self.inspection(),native_evidence=evidence)
        self.assertEqual(restarted._inventory.read('assignment.json'),assignment)
        self.assertEqual(self.run_stream.messages,[])
        raw,evidence=await self.fresh(case)
        owner=await restarted.open(raw,task_inspection=self.inspection(),native_evidence=evidence)
        await self.start_owned(owner,raw,evidence)
        first=self.run_stream.messages[0].data
        self.assertEqual(strict_loads(first)['state']['originalEnvelope'],strict_loads(raw))
        self.assertEqual(self.run_stream.creates,1)
        reopened=await self.restart(restarted);retained=await reopened.existing()
        self.assertIsNotNone(retained)
        self.assertEqual((await retained._load())[0].records[0].record,first)
        self.assertEqual(self.commands,[])

    async def test_lost_stream_create_reply_keeps_exact_source_and_token(self):
        case,admission=await self.persistent_case();self.run_stream.lose_create=True
        await admission.open(case['raw'],task_inspection=self.inspection(),native_evidence=case['evidence'])
        source=admission._inventory.read('source.json');reservation=admission._inventory.read('reservation.json')
        restarted=await self.restart(admission)
        self.assertIsNone(await restarted.existing())
        self.assertEqual(restarted._inventory.read('source.json'),source)
        self.assertEqual(restarted._inventory.read('reservation.json'),reservation)
        self.assertEqual(self.run_stream.creates,1)
        self.assertEqual(self.run_stream.messages,[])
        self.assertEqual(self.commands,[])

    async def test_preexisting_unowned_stream_refuses_without_adoption(self):
        case,admission=await self.persistent_case();self.run_stream.exists=True
        with self.assertRaisesRegex(ContractError,'^capability_process_unenrolled_stream$'):
            await admission.open(case['raw'],task_inspection=self.inspection(),native_evidence=case['evidence'])
        self.assertIsNone(admission._inventory.read('reservation.json'))
        self.assertEqual(self.run_stream.creates,0)
        self.assertEqual(self.commands,[])

    async def source_refusal(self,kind):
        case,admission=await self.persistent_case()
        owner=await admission.open(case['raw'],task_inspection=self.inspection(),native_evidence=case['evidence'])
        await self.start_owned(owner,case['raw'],case['evidence'])
        first=self.run_stream.messages[0].data
        sequence=len(self.run_stream.messages)
        self.assertEqual(admission._inventory.floor(),sequence)
        restarted=await self.restart(admission)
        if kind=='floor':self.run_stream.messages=[]
        elif kind=='created':self.run_stream.created+=timedelta(microseconds=1)
        else:self.run_stream.config.metadata={'agentmuxProcessRun':'f'*64}
        with self.assertRaises(ContractError):await restarted.existing()
        self.assertEqual(self.run_stream.creates,1)
        self.assertEqual(restarted._inventory.floor(),sequence)
        if kind!='floor':self.assertEqual(self.run_stream.messages[0].data,first)
        self.assertEqual(self.commands,[])

    async def test_observed_sequence_cannot_roll_back_on_restart(self):await self.source_refusal('floor')
    async def test_recreated_source_cannot_be_adopted_on_restart(self):await self.source_refusal('created')
    async def test_changed_reservation_token_cannot_be_adopted_on_restart(self):await self.source_refusal('token')


for _name in dir(ProcessNativeDeliveryTests):
    if _name.startswith('test_') and _name not in vars(ProcessAdmissionTests):setattr(ProcessAdmissionTests,_name,None)
