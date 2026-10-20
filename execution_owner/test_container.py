"""Current signed admission, retained intent and container adapter boundaries."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, payload_digest
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED, record
from capability_owner import test_workspace_host as workspace_support
from . import test_plans as plan_support
from .container import TaskContainerAdapter, RetainedContainerIntent
from .docker_engine import DockerEngine, DockerSelection
from .network import SelectedNetwork


class ContainerTests(plan_support.ExecutionPlanTests):
    # This class supplies B-specific checks; do not rerun A's accepted suite by
    # inheriting its test methods. The reusable fixture methods remain available.
    live=False
    git=workspace_support.WorkspaceCheckoutTests.git

    def setUp(self):
        super().setUp()
        self.profile['isolation']['workerUID']=501
        self.profile['recipe']={'kind':'python-script-v1','path':'file',
            'sha256':'sha256:'+hashlib.sha256(b'original workspace bytes').hexdigest()}
        self.profile['limits']['offlineSeconds']=30
        self.profile['limits']['maxSeconds']=60
        self.plans=self.make_owner();self.addAsyncCleanup(self.plans.close)
        if self.live:
            for module in ('identity.ingress','identity.commands','identity.service','state_owner.ledger',
                    'state_owner.task','execution_owner.plans'):
                patch(module+'.datetime',datetime).start()
            def current(value):
                if isinstance(value,dict):
                    for key,item in value.items():
                        if key=='issuedAt':value[key]=(datetime.now(timezone.utc)-timedelta(seconds=2)).isoformat().replace('+00:00','Z')
                        elif key in ('expiresAt','deadline'):value[key]=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat().replace('+00:00','Z')
                        else:current(item)
                elif isinstance(value,list):
                    for item in value:current(item)
            current(self.record);self.sync()

    async def asyncSetUp(self):
        retention=self.policy
        await workspace_support.WorkspaceCheckoutTests.asyncSetUp(self)
        self.workspace_policy=self.policy
        self.policy=retention
        self.selection=DockerSelection(str(Path(sys.executable).resolve()),'desktop-linux','unix:///tmp/selected.sock',
            'selected-engine','29.8.2',str(Path.home()/'.docker'),'sha256:'+'a'*64)
        self.engine=DockerEngine(self.selection)
        self.adapter=TaskContainerAdapter(self.plans,self.engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.addAsyncCleanup(self.adapter.close)
        self.observed=None
        self.commands=[]
        self.engine.check_transport=AsyncMock()
        self.engine.check=AsyncMock(return_value={'Id':self.selection.image_id,'Config':{}})
        self.engine.find=AsyncMock(side_effect=lambda name:copy.deepcopy(self.observed))
        self.engine.inspect=AsyncMock(side_effect=lambda cid:copy.deepcopy(self.observed))
        self.engine._run=AsyncMock(side_effect=self.command)
        self.engine.exec_fixed=AsyncMock(return_value=b'')

    def possession(self, **changes):
        if self.live:changes['now']=datetime.now(timezone.utc)
        return super().possession(**changes)

    def request(self, *args, **kwargs):
        raw=super().request(*args,**kwargs)
        if not self.live:return raw
        value=strict_loads(raw);now=datetime.now(timezone.utc)
        value['operation']['deadline']=(now+timedelta(seconds=30)).isoformat().replace('+00:00','Z')
        claims=value['ingressAttestation']['claims']
        for key in ('issuedAt','sentAt'):claims[key]=now.isoformat().replace('+00:00','Z')
        claims['expiresAt']=value['operation']['deadline']
        claims['operation']=copy.deepcopy(value['operation'])
        value['sentAt']=claims['sentAt']
        value['ingressAttestation']['signature']=sign_claims(claims,SEED)
        return canonical_bytes(value)

    async def authorized(self):
        await self.reserve()
        if self.live:
            now=datetime.now(timezone.utc)
            self.plan.update(issuedAt=(now-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),
                expiresAt=(now+timedelta(seconds=60)).isoformat().replace('+00:00','Z'))
        await self.enroll()
        admission=await self.plans.admit_start(self.start(),task_inspection=self.inspection())
        binding=strict_loads(admission.binding)
        owner=OwnerBinding('hub-one','execution',binding['runRef']['id'],'attempt',canonical_bytes(self.scope))
        self.intent_js=FakeJetStream(self.policy);self.intent_js.config.subjects=[owner_subject(owner)]
        self.intent_ledger=OwnerLedger(self.intent_js,stream='OWNER',subject=owner_subject(owner),binding=owner,
            retention=self.policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        retained=record('execution-intent')
        retained.update(entityId=owner.entity_id,entityKind='attempt',ownerDomain='execution',
            operation=binding['originalOperation'],state={'executionBinding':binding,'executionPhase':'start-intent'},
            effects=[{'effectId':'container-'+binding['runRef']['id'].removeprefix('execution-'),
                'contractId':'execution-container-prepare','payloadDigest':payload_digest(binding),
                'grantRef':binding['originalOperation']['grantRef'],'recovery':'query-before-retry','payload':binding}],
            authorizationDecision={'operationId':binding['originalOperation']['operationId'],'decision':'allowed',
                'reason':'authorized','actorRef':binding['originalOperation']['effectiveActorRef'],
                'contractId':'capability-process-start'})
        await self.intent_ledger.append(retained,expected_sequence=0,expected_target_version=1,completion_records=0)
        return admission,RetainedContainerIntent(self.intent_ledger,admission.binding)

    async def command(self, args, **kwargs):
        self.commands.append(args[0])
        if args[0]=='create':
            run=next(iter(self.adapter._runs.values()));spec=run['spec'];limits=self.profile['limits']
            self.observed={'Id':'c'*64,'Name':'/'+spec['name'],'Image':spec['image'],
                'State':{'Status':'created','Running':False,'ExitCode':0,'Pid':0},
                'Config':{'Labels':spec['labels'],'User':str(spec['uid'])+':'+str(spec['uid']),
                    'WorkingDir':'/workspace','Entrypoint':spec['command'][:1],'Cmd':spec['command'][1:],
                    'Env':spec['environment'],'Tty':False,'OpenStdin':False},
                'HostConfig':{'Privileged':False,'ReadonlyRootfs':True,'NetworkMode':'none','PidMode':'',
                    'IpcMode':'private','UTSMode':'','CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
                    'RestartPolicy':{'Name':'no'},'LogConfig':{'Type':'none','Config':{}},
                    'Memory':limits['memoryBytes'],'MemorySwap':limits['memoryBytes'],
                    'NanoCpus':limits['cpuMillis']*1000000,'PidsLimit':limits['pids'],
                    'Tmpfs':{'/run/agentmux':spec['tmpfs']}},
                'Mounts':[{'Type':'bind','Source':spec['source'],'Destination':'/workspace','RW':True}]}
            return b'c'*64+b'\n'
        if args[0]=='start':self.observed['State'].update(Status='running',Running=True,Pid=123)
        if args[0]=='stop':self.observed['State'].update(Status='exited',Running=False,ExitCode=137,Pid=0)
        if args[0]=='rm':self.observed=None
        return b''

    async def test_prepare_requires_actual_retained_exact_intent(self):
        admission,intent=await self.authorized()
        with self.assertRaisesRegex(ContractError,'^execution_intent_required$'):
            await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=None)
        value=strict_loads(self.intent_js.messages[0].data)
        value['state']['executionPhase']='cancelled'
        self.intent_js.messages[0].data=canonical_bytes(value)
        with self.assertRaisesRegex(ContractError,'^execution_intent_required$'):
            await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        self.assertFalse(self.commands)

    async def test_prepare_start_stop_and_exact_owned_cleanup(self):
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        self.assertEqual(prepared.status,'prepared')
        reference=strict_loads(prepared.run_ref)
        await self.adapter.deliver_private(reference,admission,task_inspection=self.inspection(),intent=intent,
            worker_ref=ref('worker'),consumer_ref=ref('consumer'),material=b'noncredential-fixture')
        self.assertEqual((await self.adapter.start(reference,admission,task_inspection=self.inspection(),intent=intent)).status,'running')
        self.assertEqual((await self.adapter.stop(reference)).status,'terminal')
        await self.adapter.cleanup(reference)
        self.assertEqual(self.commands,['create','start','stop','rm'])

    async def refuse_after_inspect(self, action):
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        reference=strict_loads(prepared.run_ref)
        self.engine.exec_fixed.reset_mock()
        async def inspect_then_revoke(cid):
            self.record['state']['memberships'][0]['status']='revoked';self.sync()
            return copy.deepcopy(self.observed)
        self.engine.inspect.side_effect=inspect_then_revoke
        with self.assertRaises(ContractError):
            if action=='start':
                await self.adapter.start(reference,admission,task_inspection=self.inspection(),intent=intent)
            else:
                await self.adapter.deliver_private(reference,admission,task_inspection=self.inspection(),intent=intent,
                    worker_ref=ref('worker'),consumer_ref=ref('consumer'),material=b'noncredential-fixture')
        self.engine.exec_fixed.assert_not_awaited()
        self.engine.inspect.side_effect=lambda cid:copy.deepcopy(self.observed)
        await self.adapter.stop(reference);await self.adapter.cleanup(reference)

    async def test_revoke_at_final_inspect_refuses_start(self):
        await self.refuse_after_inspect('start')

    async def test_revoke_at_final_inspect_refuses_private_send(self):
        await self.refuse_after_inspect('deliver')

    async def test_revoke_at_find_refuses_create(self):
        admission,intent=await self.authorized()
        async def find_then_revoke(name):
            self.record['state']['memberships'][0]['status']='revoked';self.sync()
            return None
        self.engine.find.side_effect=find_then_revoke
        with self.assertRaises(ContractError):
            await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        self.assertFalse(self.commands)
        self.adapter._runs.clear()

    async def test_recovered_running_is_pending_and_cannot_start_again(self):
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        reference=strict_loads(prepared.run_ref)
        await self.adapter.start(reference,admission,task_inspection=self.inspection(),intent=intent)
        retained=await self.adapter.checkpoint()
        self.assertEqual(retained[0].resource_ref,prepared.resource_ref)
        recovered=TaskContainerAdapter(self.plans,self.engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.addAsyncCleanup(recovered.close)
        observation=await recovered.recover(intent,resource_ref=prepared.resource_ref)
        self.assertEqual(observation.status,'pending')
        with self.assertRaisesRegex(ContractError,'^execution_container_unknown$'):
            await recovered.start(reference,admission,task_inspection=self.inspection(),intent=intent)
        # Closing the checkpointed original must not mutate the transferred
        # physical resource. The recovery owner retains its exact ID.
        count=len(self.commands)
        await self.adapter.close()
        self.assertEqual(len(self.commands),count)
        self.assertEqual((await recovered.stop(reference)).status,'terminal')
        await recovered.cleanup(reference)
        self.assertEqual(self.commands.count('create'),1)

    async def test_uncertain_create_is_not_repeated_or_started(self):
        admission,intent=await self.authorized()
        async def create_then_lose(args,**kwargs):
            result=await self.command(args,**kwargs)
            if args[0]=='create':raise ContractError('execution_engine_command_unknown')
            return result
        self.engine._run.side_effect=create_then_lose
        with self.assertRaisesRegex(ContractError,'^execution_engine_command_unknown$'):
            await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        observed=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        self.assertEqual(observed.status,'pending')
        with self.assertRaises(ContractError):
            await self.adapter.start(strict_loads(observed.run_ref),admission,
                task_inspection=self.inspection(),intent=intent)
        self.assertEqual(self.commands,['create'])
        self.engine._run.side_effect=self.command

    async def test_changed_inspect_cannot_stop_or_clean_unrelated_resource(self):
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        reference=strict_loads(prepared.run_ref)
        original=copy.deepcopy(self.observed)
        for mutate in (lambda x:x.update(Id='d'*64), lambda x:x['Config']['Labels'].update(other='owner'),
                lambda x:x['HostConfig'].update(Privileged=True),
                lambda x:x['HostConfig'].update(NetworkMode='host'),
                lambda x:x['HostConfig'].update(PidMode='host'),
                lambda x:x['HostConfig'].update(CapAdd=['SYS_ADMIN']),
                lambda x:x['Mounts'].append({'Type':'bind','Source':'/other','Destination':'/other','RW':True}),
                lambda x:x.update(Config=None), lambda x:x.update(HostConfig=None),
                lambda x:x.update(Id=None), lambda x:x['HostConfig'].update(RestartPolicy=None),
                lambda x:x.update(Mounts=[None]), lambda x:x.pop('State')):
            self.observed=copy.deepcopy(original);mutate(self.observed)
            count=len(self.commands)
            self.assertEqual((await self.adapter.observe(reference)).status,'unknown')
            with self.assertRaises(ContractError):await self.adapter.stop(reference)
            with self.assertRaises(ContractError):await self.adapter.cleanup(reference)
            self.assertEqual(len(self.commands),count)
        self.observed=original

    async def test_deadline_during_final_inspect_refuses_private_delivery(self):
        from identity.test_service import _Clock
        from identity.test_authority import NOW
        class ExpiredClock(_Clock):
            @classmethod
            def now(cls,tz=None):return NOW+timedelta(seconds=31)
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        reference=strict_loads(prepared.run_ref)
        self.engine.exec_fixed.reset_mock()
        async def inspected(cid):
            patch('execution_owner.plans.datetime',ExpiredClock).start()
            return copy.deepcopy(self.observed)
        self.engine.inspect.side_effect=inspected
        with self.assertRaisesRegex(ContractError,'^execution_admission_expired$'):
            await self.adapter.deliver_private(reference,admission,task_inspection=self.inspection(),intent=intent,
                worker_ref=ref('worker'),consumer_ref=ref('consumer'),material=b'noncredential-fixture')
        self.engine.exec_fixed.assert_not_awaited()
        self.engine.inspect.side_effect=lambda cid:copy.deepcopy(self.observed)


    async def test_same_instance_recovery_preserves_original_relay_handles(self):
        admission,intent=await self.authorized()
        prepared=await self.adapter.prepare(admission,task_inspection=self.inspection(),intent=intent)
        run=next(iter(self.adapter._runs.values()))
        release=asyncio.Event()
        original=asyncio.create_task(release.wait(),name='original-private-relay')
        run['relay_task']=original
        try:
            with self.assertRaisesRegex(ContractError,'^execution_recovery_already_owned$'):
                await self.adapter.recover(intent,resource_ref=prepared.resource_ref)
            self.assertIs(next(iter(self.adapter._runs.values())),run)
            self.assertIs(run['relay_task'],original)
            self.assertFalse(original.done())
        finally:
            release.set();await original
            run['relay_task']=None



# A's tests are not part of B's inherited fixture. Keep only this class's tests.
for _name in vars(plan_support.ExecutionPlanTests):
    if _name.startswith('test_') and _name not in vars(ContainerTests):setattr(ContainerTests,_name,None)
