"""Native C delivery and real scoped TLS/NATS task-service use."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import platform
import secrets
import sys
from types import SimpleNamespace

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from capability_owner import test_live as tls_support
from hub.nats_transport import new_client
from identity.test_authority import ref, SEED
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.ledger import OwnerLedger, StreamIdentity, owner_subject
from state_owner.task_service import TaskService
from tests.storage.run import Broker
from .container import TaskContainerAdapter, RetainedContainerIntent
from .docker_engine import DockerEngine, DockerSelection
from .network import SelectedNetwork
from .test_container import ContainerTests
from .test_container_live import IMAGE
from .test_task_credentials import TaskCredentialTests
from .task_credentials import TaskCredentialPolicy


def stamp(value):return value.isoformat(timespec='microseconds').replace('+00:00','Z')


class NativeTaskCredentialTests(TaskCredentialTests):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_EXECUTION_DOCKER_LIVE')!='1' or os.environ.get('AMX_TASK_LIVE')!='1':
            raise RuntimeError('A coordinated C Docker and broker slot is required')
        if platform.system()!='Darwin' or platform.machine()!='arm64':raise RuntimeError('Native macOS ARM64 is required')
        super().setUpClass()

    async def asyncSetUp(self):
        await super().asyncSetUp()
        asyncio.get_running_loop().slow_callback_duration=10
        self.live_adapter=None
        # Preserve the exact mounted source if an owned native original remains.
        self._cleanups=[item for item in self._cleanups if not (
            getattr(item[0],'__self__',None) is self.directory and getattr(item[0],'__name__','')=='cleanup')]
        def directory_cleanup():
            runs=[] if self.live_adapter is None else list(self.live_adapter._runs.values())
            if any(not run.get('removed') for run in runs):self.directory._finalizer.detach()
            else:self.directory.cleanup()
        self._cleanups.insert(0,(directory_cleanup,(),{}))
        await self.credentials.close()
        fixture=tls_support.LiveCapabilityTests()
        self.tls_fixture=fixture
        fixture.directory=self.path/'broker';fixture.directory.mkdir(mode=0o700)
        fixture.connections=[];fixture.errors={};fixture.permission_events={};fixture.keep_directory=False
        fixture.inbox_prefixes={role:'_INBOX.'+secrets.token_hex(16)
            for role in ('provisioner','identity','storage','host','other-scope')}
        fixture.read_contract='task-inspect';fixture.boundary_checks=False;fixture.broker_stream_limit=8
        fixture.broker_disk_storage=getattr(self,'broker_disk_storage','16m')
        fixture.subjects={'IDENTITY':self.service.ledger._subject,'DATA':self.owner._ledger._subject,'OTHER':'fixture.other'}
        fixture.identity_subject=self.service.subject
        fixture.read_subject='fixture.read';fixture.other_subject='fixture.other.command'
        fixture.broker=Broker(fixture.directory)
        async def close_broker():
            for connection in tuple(fixture.connections):await connection.close()
            fixture.broker.stop()
        self.addAsyncCleanup(close_broker)
        fixture._configure_tls_and_users()
        self.admin=await fixture.start_tls_broker()
        self.account_public=fixture.account_public_key
        found=[]
        for path in (fixture.directory/'nsc-keys'/'keys').rglob('*.nk'):
            raw=path.read_bytes().strip();key=None
            try:
                key=nkeys.from_seed(raw)
                if key.public_key.decode()==self.account_public:found.append(raw)
            finally:
                if key is not None:key.wipe()
        self.assertEqual(len(found),1);self.account_seed=found[0]
        self.record['state']['applicationAccounts'][0]['accountPublicKey']=self.account_public
        org={'organizationId':'org-one','projectId':None,'workspaceId':None}
        self.record['state']['memberships'].append({'ref':ref('credential-admin-org-member'),
            'identityRef':ref('administrator'),'scope':org,'status':'active'})
        base=copy.deepcopy(self.record['state']['grants'][0])
        for contract in ('identity-enroll','identity-revoke'):
            self.record['state']['grants'].append({**copy.deepcopy(base),'ref':ref(contract+'-credential-admin'),
                'callerRef':ref('administrator'),'actorRef':ref('administrator'),'scope':org,
                'contractId':contract,'resourceId':'authority-one'})
        self.sync()
        async def retained(stream,old):
            records=(await old.current()).records
            info=await self.admin.jetstream().add_stream(self.policy.stream_config(stream=stream,subject=old._subject))
            ledger=OwnerLedger(self.admin.jetstream(),stream=stream,subject=old._subject,binding=old._binding,
                retention=self.policy,stream_identity=StreamIdentity(info.created,0),require_completion_budget=True)
            for item in records:await ledger.append(strict_loads(item.record),expected_sequence=item.sequence-1,completion_records=0)
            return ledger
        identity=await retained('IDENTITY',self.service.ledger)
        self.service.ledger=identity;self.service.reader._ledger=identity;self.service.owner._ledger=identity
        self.owner._ledger=await retained('TASK',self.owner._ledger)
        self.plan_ledger=await retained('PLAN',self.plan_ledger)
        self.credential_ledger=await retained('CREDENTIAL',self.credential_ledger)
        self.profile['image']=IMAGE;self.plans=self.make_owner();self.addAsyncCleanup(self.plans.close)
        self.real_engine=DockerEngine(DockerSelection(str(Path('/Users/ryan/.docker/bin/docker').resolve()),
            'desktop-linux','unix:///Users/ryan/.docker/run/docker.sock','bf61e5bf-20ff-4b43-a588-d6c46ed9e664',
            '29.8.2',str(Path.home()/'.docker'),IMAGE.split('@')[1]))
        self.adapter=TaskContainerAdapter(self.plans,self.real_engine,self.host,workspace_ref=ref('workspace'),
            network=SelectedNetwork(ref('network')))
        self.live_adapter=self.adapter;self.addAsyncCleanup(self.adapter.close)
        self.task_service=TaskService(self.owner,self.service.ingress,connection=None,
            service_identity_ref=ref('consumer'),service_instance_id='consumer-instance',
            signing_key_ref=ref('consumer-issuer'),signing_seed=SEED,
            requester_reply_prefix='_INBOX.task_consumer_00000001',account_public_key=self.account_public)
        self.credential_policy=TaskCredentialPolicy(canonical_bytes(ref('consumer')),fixture.broker.url,
            fixture.server_name,fixture.ca_file.read_bytes(),fixture.leaf_digest,
            canonical_bytes(ref('application-account')),self.account_public,canonical_bytes(ref('issuer')),
            '_INBOX.task_consumer_00000001')
        admin_root=self.path/'live-account-custody';admin_root.mkdir(mode=0o700)
        self.account_custody=ScopedSecretCustody(admin_root,self.service.reader)
        self.account_payload['accountPublicKey']=self.account_public;self.account_request=self.account_envelope()
        snapshot=await self.service.reader.current()
        self.account_custody._store.provision(_resolved_binding(snapshot,self.account_request,
            'nats-account-issuer',datetime.now(timezone.utc)),self.account_seed)
        self.credentials=self.make_credentials()

    async def admin_change(self,contract,payload):
        snapshot=await self.service.reader.current();now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':ref('administrator-transport'),
            'grantRef':ref(contract+'-credential-admin'),'operationId':contract+'-'+secrets.token_hex(8),
            'expectedVersion':snapshot.sequence,'contractId':contract,'payload':payload,'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        request={'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,bytes(reversed(SEED)))}
        return await self.service.handle(canonical_bytes(request))

    async def live_phase(self,name):
        raw=strict_loads(self.phase(name))
        raw['operation']['expectedVersion']=(await self.credential_ledger.current()).sequence
        claims=raw['ingressAttestation']['claims'];claims['operation']=copy.deepcopy(raw['operation'])
        raw['ingressAttestation']['signature']=sign_claims(claims,SEED)
        return canonical_bytes(raw)

    async def timing(self,stage):
        now=datetime.now(timezone.utc)
        record=strict_loads((await self.service.reader.current()).record)
        future=[]
        for collection in ('issuers','transports','grants','approvals'):
            for row in record['state'][collection]:
                if row['status']!='active':continue
                for field in ('issuedAt','expiresAt'):
                    boundary=datetime.fromisoformat(row[field])
                    if boundary>now:future.append((round((boundary-now).total_seconds(),3),collection,row['ref']['id'],field))
        bound=strict_loads(self.admission.binding)
        values={'stage':stage,'admissionSeconds':round((self.admission.valid_until-now).total_seconds(),3),
            'executionSeconds':round((datetime.fromisoformat(bound['executionValidUntil'])-now).total_seconds(),3),
            'originalSeconds':round((datetime.fromisoformat(bound['originalOperation']['deadline'])-now).total_seconds(),3),
            'nearestAuthorityBoundaries':sorted(future)[:3]}
        if hasattr(self,'credential_record'):values['credentialSeconds']=round(self.credential_record['expiresUnix']-now.timestamp(),3)
        print('Owned C timing: '+str(values),file=sys.stderr)

    async def ready(self,*,physical=False):
        self.admission,self.intent=await self.authorized();self.run_ref=strict_loads(self.admission.binding)['runRef']
        await self.timing('admitted')
        # A's intent is copied once into this fixture's real retained stream.
        old=self.intent_ledger;info=await self.admin.jetstream().add_stream(
            self.policy.stream_config(stream='EXECUTION',subject=old._subject))
        retained=OwnerLedger(self.admin.jetstream(),stream='EXECUTION',subject=old._subject,binding=old._binding,
            retention=self.policy,stream_identity=StreamIdentity(info.created,0),require_completion_budget=True)
        first=(await old.current()).latest
        await retained.append(strict_loads(first.record),expected_sequence=0,expected_target_version=1,completion_records=0)
        self.intent=RetainedContainerIntent(retained,self.admission.binding)
        self.prepare_raw=await self.live_phase('prepare')
        result=strict_loads(await self.credentials.prepare(self.prepare_raw,self.admission,
            task_inspection=self.inspection(),account_request=self.account_request))
        self.credential_record=result['record'];self.enrollment=result['enrollment']
        await self.timing('credential-prepared')
        await self.admin_change('identity-enroll',self.enrollment)
        await self.timing('enrolled')
        if physical:await self.adapter.prepare(self.admission,task_inspection=self.inspection(),intent=self.intent)
        await self.timing('container-prepared')
        return result

    async def deliver(self):
        self.deliver_raw=await self.live_phase('deliver')
        await self.timing('before-delivery')
        return await self.credentials.deliver(self.deliver_raw,self.admission,task_inspection=self.inspection(),
            account_request=self.account_request,intent=self.intent)

    async def test_native_private_delivery_real_scoped_task_service_and_revocation(self):
        await self.ready(physical=True);await self.deliver()
        state=strict_loads(await self.credentials.observe(await self.live_phase('observe')))
        self.assertEqual(state['phase'],'delivered')
        result=strict_loads(await self.credentials.inspect_task(self.deliver_raw,self.admission,
            task_inspection=self.inspection(),account_request=self.account_request,intent=self.intent))
        self.assertEqual(result,{'generationRef':self.credential_record['generationRef'],'runRef':self.run_ref,
            'taskRef':self.credential_record['taskRef'],'consumerRef':ref('consumer'),'status':'inspected'})
        self.assertFalse(self.credentials._clients or self.credentials._handlers or self.credentials._proofs)
        await self.admin_change('identity-revoke',{'authorityId':'authority-one','targetRef':self.credential_record['transportRef']})
        with self.assertRaisesRegex(ContractError,'^task_credential_enrollment_unavailable$'):
            await self.credentials.inspect_task(self.deliver_raw,self.admission,
                task_inspection=self.inspection(),account_request=self.account_request,intent=self.intent)
        self.assertEqual((await self.adapter.stop(self.run_ref)).status,'terminal')
        await self.credentials.retire(await self.live_phase('retire'))
        await self.adapter.cleanup(self.run_ref)
        self.assertFalse(self.real_engine._jobs)
        name=next(iter(self.adapter._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))


for _name in dir(TaskCredentialTests):
    if _name.startswith('test_') and _name not in vars(NativeTaskCredentialTests):setattr(NativeTaskCredentialTests,_name,None)
