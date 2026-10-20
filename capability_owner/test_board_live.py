"""Selected board publishers on the existing coordinated TLS/JWT fixture.

Import and collection start no broker. The coordinator must grant the live slot.
These checks do not qualify all legacy writers or installed composition.
"""
import asyncio
import base64
import copy
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import platform
import secrets
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from nats.js.api import KeyValueConfig
from nats.js.errors import APIError
from agentmux_contracts import ContractError,canonical_bytes,strict_loads
from hub.fed.board_services import SharedBoardStore
from hub.fed.plugins.board import Board
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.store import Store
from hub.tests.test_fed_unit import policy as board_policy
from identity.service import IdentityService
from identity.capability_service import evaluate_capability_service_request
from identity.test_authority import ref,SEED
from identity.test_commands import command_fixture
from identity.test_native_bridge import HOST_SEED,native_row
from native_security.nats_credentials import board_publisher_policy,validate_board_publisher
from state_owner.ledger import OwnerBinding,OwnerLedger,StreamIdentity,owner_subject
from state_owner.retention import Retention
from state_owner import test_task_live as task_fixture
from tests.storage.run import Broker
from . import test_live as tls_fixture
from .test_live import packet,stamp
from .board_allocation import BoardAllocationResource,BoardAllocationTarget
from .board_allocation_journal import BoardAllocationJournal
from .board_allocation_owner import BoardAllocationOwner
from .board_journal import BoardOperationJournal
from .board_owner import BoardActor,BoardMutationOwner
from .board_phase_signer import BoardPhaseSigner
from .board_publisher import BoardPublisher
from .board_target import BoardTargetBinding
from .federation_board import FederationBoardResource
from .reply_service import CapabilityReplyService,verify_capability_response


OWNER_SEED=bytes([53])*32


class LiveBoardPublisherTests(unittest.IsolatedAsyncioTestCase):
    _configure_tls_and_users=tls_fixture.LiveCapabilityTests._configure_tls_and_users
    start_tls_broker=tls_fixture.LiveCapabilityTests.start_tls_broker
    connect=tls_fixture.LiveCapabilityTests.connect
    exchange=tls_fixture.LiveCapabilityTests.exchange
    command=tls_fixture.LiveCapabilityTests.command
    native=tls_fixture.LiveCapabilityTests.native
    wait_permissions=tls_fixture.LiveCapabilityTests.wait_permissions
    custody=task_fixture.LiveTaskTests.custody
    read_contract='capability-storage-write'
    boundary_checks=False
    tls_server_name='localhost'
    broker_stream_limit=4

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_BOARD_LIVE')!='1':
            raise RuntimeError('A coordinated board live slot is required')
        if platform.system()!='Darwin' or platform.machine()!='arm64':
            raise RuntimeError('Native macOS ARM64 is required')

    def configure_broker_policies(self,policies,reads):
        policies['storage']={'publish':{'allow':['amx.fixture.receiver.noop']},
            'subscribe':{'allow':[self.read_subject,self.outcome_subject]}}
        policies['host']['publish']['allow'].append(self.outcome_subject)
        for role,entity,stream,selection in (
                ('card','task-one','DATA',{'card_key':'SH-1'}),
                ('prefix','prefix-one','OTHER',{'counter_prefix':'SH'})):
            selected=dict(hub_id='hub-one',entity_id=entity,scope=self.scope,stream=stream,
                reply_prefix=self.inbox_prefixes[role],repository_id=self.rid,**selection)
            self.selections[role]=selected
            policy=board_publisher_policy(**selected)
            policies[role]={'publish':{'allow':list(policy.publish_subjects)},'subscribe':{'allow':[]}}

    async def asyncSetUp(self):
        self.directory=Path(tempfile.mkdtemp(prefix='agentmux-board-live-')).resolve()
        self.connections,self.histories,self.publishers,self.responders=[],[],[],[]
        self.identity=self.broker=self.store=None
        self.success=self.keep_directory=False
        self.addAsyncCleanup(self.cleanup)
        self.errors,self.permission_events,self.selections={},{},{}
        self.inbox_prefixes={role:'_INBOX.'+secrets.token_hex(16) for role in
            ('provisioner','identity','storage','host','other-scope','card','prefix')}
        self.scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None}
        self.policy=Retention(4_194_304,1_048_576)
        self.rid=board_policy().rid_of('falcon')
        org_scope={'organizationId':'org-one','projectId':None,'workspaceId':None}
        self.bindings={'IDENTITY':OwnerBinding('hub-one','identity','authority-one','identity-authority',canonical_bytes(org_scope)),
            **{stream:OwnerBinding('hub-one','federation-board-operations',entity,'attempt',canonical_bytes(self.scope))
                for stream,entity in (('DATA','task-one'),('OTHER','prefix-one'))}}
        self.subjects={name:owner_subject(binding) for name,binding in self.bindings.items()}
        self.identity_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        base='amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.'
        self.read_subject=base+'storage-owner.command'
        self.outcome_subject=base+'outcome-owner.command'
        self.other_subject='amx.v1.h.hub-one.o.other-org.p._.w._.capability.storage-owner.command'
        self.broker=Broker(self.directory)
        self._configure_tls_and_users()
        self.admin=await self.start_tls_broker()
        infos={name:await self.admin.jetstream().add_stream(self.policy.stream_config(stream=name,subject=subject))
            for name,subject in self.subjects.items()}
        self.streams={name:StreamIdentity(info.created,0) for name,info in infos.items()}
        self.kv=await self.admin.jetstream().create_key_value(KeyValueConfig(bucket='am_board',history=1,max_bytes=2_097_152))
        board_info=await self.admin.jetstream().stream_info('KV_am_board')
        self.board_stream=StreamIdentity(board_info.created,0)
        self.initial_card={'key':'SH-1','rid':self.rid,'title':'Original','status':'todo',
            'comments':[],'history':[],'unknownFutureField':{'retained':[None,42]}}
        self.counter_revision=await self.kv.put(self.rid+'.seq.SH',b'1')
        self.card_revision=await self.kv.put(self.rid+'.card.SH-1',canonical_bytes(self.initial_card))
        initial=self.initial_authority()
        bootstrap=OwnerLedger(self.admin.jetstream(),stream='IDENTITY',subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'],retention=self.policy,stream_identity=self.streams['IDENTITY'])
        await bootstrap.append(initial,expected_sequence=0)
        connection=await self.connect('identity')
        history,backup,checkpoint=self.custody('identity','IDENTITY')
        from state_owner.checkpoints import CheckpointReceipt
        async def committed(receipt):
            await checkpoint.committed(CheckpointReceipt(receipt.manifest_path,receipt.digest,receipt.cursor))
        self.identity=IdentityService(connection,stream='IDENTITY',stream_identity=self.streams['IDENTITY'],
            retention=self.policy,hub_id='hub-one',entity_id='authority-one',profile_id='profile-one',
            organization_id='org-one',issuer_ref=ref('issuer'),signing_seed=SEED,history=history,
            checkpoint_path=checkpoint.checkpoint_prefix,checkpoint_committed=committed,
            backup_host=backup,backup_key_id='backup-one')
        await self.identity.start()
        self.host=await self.connect('host')
        for row in (self.parent,self.row):
            await self.command('identity-native-instance-set',ref('native-admin'),
                {'authorityId':'authority-one','record':row,'previousRef':None})
        self.storage=await self.connect('storage')
        self.store=Store(str(self.directory/'board.sqlite'))
        self.store.repo_add('falcon')
        for statement in Board.tables:self.store.db.execute(statement)
        async def db(function,*args,**kwargs):return function(*args,**kwargs)
        self.domain=SimpleNamespace(me='nick',node='mac',store=self.store,db=db,policy=board_policy(),presence={},
            hub=SimpleNamespace(sender_of=lambda caller:caller),kick=lambda:None)
        for name in ('sender_of','resolve_repo','address_of','stage','publish'):
            setattr(self.domain,name,getattr(Federation,name).__get__(self.domain))
        for role in ('prefix','card'):
            selected=self.selections[role]
            raw=self.credentials[role].read_bytes()
            credential=validate_board_publisher(raw,account_public_key=self.account_public_key,**selected)
            publisher=BoardPublisher(credentials=raw,account_public_key=self.account_public_key,
                user_public_key=credential.public_key,server_url='tls://localhost:'+str(self.broker.port),
                tls_context=self.tls,leaf_certificate_sha256=self.leaf_digest,**selected)
            self.publishers.append(publisher)
            await publisher.start()
            setattr(self,role+'_publisher',publisher)
        self.install_owners()
        for service in ('storage-owner','outcome-owner'):
            responder=CapabilityReplyService(self.identity.reader,resources=[self.card_resource],hub_id='hub-one',
                profile_id='profile-one',authority_id='authority-one',service_id=service,
                service_identity_ref=ref('service'),service_instance_id='ingress-one',signing_key_ref=ref('issuer'),
                signing_seed=SEED,request_signing_key_ref=ref('issuer'),connection=self.storage,board_routes=[self.route])
            self.responders.append(responder)
            await responder.start()

    def initial_authority(self):
        initial,_=command_fixture()
        initial.update(entityVersion=1,previousRevision=0,effects=[],artifacts=[],repository=None)
        initial['operation'].update(scope=strict_loads(self.bindings['IDENTITY'].scope),expectedVersion=0)
        state=initial['state']
        base=copy.deepcopy(state['grants'][0])
        for name,kind in (('host','service'),('plugin','plugin'),('parent-plugin','plugin'),('board-owner','service')):
            state['identities'].append({'ref':ref(name),'kind':kind,'principalId':name+'-one',
                'status':'active','externalIdentity':None})
        for identity,seed in (('host',HOST_SEED),('board-owner',OWNER_SEED)):
            transport=copy.deepcopy(state['transports'][0])
            transport.update(ref=ref('host-transport' if identity=='host' else 'owner-transport'),
                identityRef=ref(identity),publicKey=base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('='))
            state['transports'].append(transport)
        for identity in ('human','host','board-owner'):
            member=copy.deepcopy(state['memberships'][0])
            member.update(ref=ref(identity+'-project-member'),identityRef=ref(identity),scope=copy.deepcopy(self.scope))
            state['memberships'].append(member)
        grants=[('native-admin','identity-native-instance-set','authority-one',None,None),
            ('host-prepare','native-authority-prepare-domain-call','plugin-one','host',self.scope),
            ('host-parent-recheck','native-authority-recheck','parent-one','host',self.scope)]
        for name in ('capability-storage-write','capability-outcome-query','federation-board-command'):
            grants.append((name,name,'task-one',None,self.scope))
        for name,contract in (('allocation-command','federation-board-command'),('allocation-query','capability-outcome-query')):
            grants.append((name,contract,'prefix-one',None,self.scope))
        for prefix,entity in (('','task-one'),('allocation-','prefix-one')):
            for phase in ('dispatch','complete'):
                name=prefix+phase
                grants.append((name,'federation-board-'+phase,entity,'board-owner',self.scope))
        for name,contract,resource,identity,scope in grants:
            grant=copy.deepcopy(base)
            grant.update(ref=ref(name),contractId=contract,resourceId=resource)
            if identity is not None:grant.update(callerRef=ref(identity),actorRef=ref(identity))
            if scope is not None:grant['scope']=copy.deepcopy(scope)
            state['grants'].append(grant)
        self.row=native_row()
        self.row['facts']['grant'].update(scope=copy.deepcopy(self.scope),actions=['write','inspect'])
        self.row['facts']['policy'].update(scope=copy.deepcopy(self.scope),decisions=[
            {'access':{'action':action,'resourceClass':resource,'resourceId':'task-one'},'outcome':'allow'}
            for action,resource in (('write','storage'),('inspect','outcome'))])
        self.row['facts']['domainBindings']=[{'id':binding,'contractId':contract,'action':action,
            'resourceClass':resource,'resourceIds':['task-one']} for binding,contract,action,resource in (
                ('board-write','capability-storage-write','write','storage'),
                ('board-outcome','capability-outcome-query','inspect','outcome'))]
        self.parent=copy.deepcopy(self.row)
        self.parent.update(ref=ref('parent-row'),identityRef=ref('parent-plugin'))
        self.parent['owner'].update(instanceId='parent-one',epoch='c'*64)
        self.parent['facts']['grant'].update(grantId='parent-grant',subjectInstanceId='parent-one',policyRef=ref('parent-policy'))
        self.parent['facts']['policy'].update(reference=ref('parent-policy'),subjectInstanceId='parent-one')
        self.row.update(relationship='private',parentOwner=copy.deepcopy(self.parent['owner']))
        self.row['facts']['grant']['parentGrantRef']=ref('parent-grant')
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['parentAccess']=[copy.deepcopy(item['access']) for item in self.parent['facts']['policy']['decisions']]
        now=datetime.now(timezone.utc)
        def current_times(value):
            if type(value) is dict:
                for key,item in value.items():
                    if key=='issuedAt':value[key]=stamp(now-timedelta(seconds=30))
                    elif key in ('expiresAt','deadline'):value[key]=stamp(now+timedelta(minutes=5))
                    elif key=='recordedAt':value[key]=stamp(now)
                    else:current_times(item)
            elif type(value) is list:
                for item in value:current_times(item)
        for value in (initial,self.row,self.parent):current_times(value)
        self.issuer_public=state['issuers'][0]['publicKey']
        return initial

    def install_owners(self):
        actors=(BoardActor(ref('human'),ref('transport'),'peer:nick','operator'),)
        def domain(publisher):
            owner=copy.copy(self.domain)
            owner.js,owner.nc,owner.session=publisher.jetstream,publisher._connection,publisher._session
            return SharedBoardStore(owner)
        def journal(stream,kind,target):
            publisher=self.card_publisher if stream=='DATA' else self.prefix_publisher
            ledger=OwnerLedger(publisher.jetstream,stream=stream,subject=self.subjects[stream],binding=self.bindings[stream],
                retention=self.policy,stream_identity=self.streams[stream],require_completion_budget=True)
            return kind(ledger,self.identity.reader,owner_service_identity_ref=ref('board-owner'),target_binding=target)
        def signer(selected,prefix=''):
            return BoardPhaseSigner(selected,self.identity.ingress,transport_ref=ref('owner-transport'),signing_seed=OWNER_SEED,
                grants={'federation-board-'+phase:ref(prefix+phase) for phase in ('dispatch','complete')})
        allocation_target=BoardAllocationTarget(self.rid,'SH',self.board_stream)
        prefix_resource=BoardAllocationResource(OwnerBinding('hub-one','federation-board','prefix-one','board-prefix',
            canonical_bytes(self.scope)),domain(self.prefix_publisher),'falcon',allocation_target)
        prefix_journal=journal('OTHER',BoardAllocationJournal,allocation_target)
        self.prefix_owner=BoardAllocationOwner(prefix_resource,prefix_journal,signer(prefix_journal,'allocation-'),actors=actors)
        prefix_route=self.prefix_publisher.bind_allocation(self.prefix_owner)
        self.card_resource=FederationBoardResource(OwnerBinding('hub-one','federation-board','task-one','board-card',
            canonical_bytes(self.scope)),domain(self.card_publisher),'falcon',self.rid,'SH-1',self.board_stream)
        card_journal=journal('DATA',BoardOperationJournal,BoardTargetBinding(self.rid,'SH-1',self.board_stream))
        self.card_owner=BoardMutationOwner(self.card_resource,card_journal,signer(card_journal),actors=actors)
        self.route=self.card_publisher.bind(self.card_owner,allocation_route=prefix_route)

    async def admit(self,contract,payload,*,operation=None,grant=None):
        now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','profileId':'profile-one','hubId':'hub-one',
            'authorityId':'authority-one','transportRef':ref('transport'),'grantRef':ref(grant or contract),
            'operationId':operation or 'board-'+secrets.token_hex(16),'expectedVersion':payload['resourceRef']['revision'],
            'contractId':contract,'payload':payload,'approvalRefs':[],'issuedAt':stamp(now),
            'expiresAt':stamp(now+timedelta(seconds=30))}
        admitted=await self.identity.ingress.admit(packet(claims,bytes(reversed(SEED))),cancellation_ref=ref('board-cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        return admitted.envelope

    async def prepare(self,inner):
        envelope=strict_loads(inner)
        snapshot=await self.identity.reader.current()
        result=await self.native('prepare-domain-call',{'operation':envelope['operation'],
            'operationAuthorityRef':{**ref('authority-one'),'revision':snapshot.sequence},
            'bindingId':'board-write' if envelope['contractId']=='capability-storage-write' else 'board-outcome',
            'contractId':envelope['contractId'],'serviceRequestId':'request_'+secrets.token_hex(32),
            'serviceReplySubject':self.host.new_inbox(),'payload':envelope['payload'],
            'originalEnvelopeBytes':base64.b64encode(inner).decode()})
        return base64.b64decode(result['serviceRequestBytes'])

    async def call(self,raw,*,expect_reply=True):
        claims=strict_loads(raw)['claims']
        subject=self.read_subject if claims['serviceId']=='storage-owner' else self.outcome_subject
        if not expect_reply:
            responder=next(item for item in self.responders if item._service==claims['serviceId'])
            actual=responder.handle
            completed=asyncio.Event()
            refusals=[]
            async def observed(*args,**kwargs):
                try:return await actual(*args,**kwargs)
                except ContractError as error:
                    refusals.append(str(error))
                    raise
                finally:completed.set()
            with patch.object(responder,'handle',side_effect=observed):
                with self.assertRaises(TimeoutError):
                    await self.exchange(self.host,subject,raw,claims['replySubject'])
                await asyncio.wait_for(completed.wait(),.5)
            self.assertEqual(refusals,['capability_service_unavailable'])
            return None
        response=await self.exchange(self.host,subject,raw,claims['replySubject'])
        return strict_loads(verify_capability_response(response,raw,public_key=self.issuer_public,
            signing_key_ref=ref('issuer'),service_identity_ref=ref('service'),service_instance_id='ingress-one',
            now=datetime.now(timezone.utc)))

    async def query(self,request):
        # Native preparation creates the downstream operation actually executed
        # by the owner. The upstream admission is not its recovery identity.
        original=strict_loads(base64.b64decode(strict_loads(request)['claims']['envelopeBytes'],validate=True))
        return await self.prepare(await self.admit('capability-outcome-query',{
            'resourceRef':original['payload']['resourceRef'],'input':{'contractId':'capability-storage-write',
                'operationId':original['operation']['operationId'],'payloadDigest':original['operation']['payloadDigest']}}))

    async def allocation(self,*,operation=None):
        counter=await self.kv.get(self.rid+'.seq.SH')
        return await self.admit('federation-board-command',{
            'resourceRef':{**ref('prefix-one'),'revision':counter.revision},'attribution':'operator',
            'input':{'command':'add','title':'Retained allocation'}},operation=operation,grant='allocation-command')

    async def allocation_query(self,original):
        envelope=strict_loads(original)
        return await self.admit('capability-outcome-query',{'resourceRef':envelope['payload']['resourceRef'],
            'input':{'contractId':'federation-board-command',**{key:envelope['operation'][key]
                for key in ('operationId','payloadDigest')}}},grant='allocation-query')

    async def restart_prefix_backend(self):
        old=self.prefix_owner
        await old.close()
        ledger=OwnerLedger(self.prefix_publisher.jetstream,stream='OTHER',subject=self.subjects['OTHER'],
            binding=self.bindings['OTHER'],retention=self.policy,stream_identity=self.streams['OTHER'],
            require_completion_budget=True)
        journal=BoardAllocationJournal(ledger,self.identity.reader,owner_service_identity_ref=ref('board-owner'),
            target_binding=old._resource.target)
        signer=BoardPhaseSigner(journal,self.identity.ingress,transport_ref=ref('owner-transport'),signing_seed=OWNER_SEED,
            grants={'federation-board-'+phase:ref('allocation-'+phase) for phase in ('dispatch','complete')})
        self.prefix_owner=BoardAllocationOwner(old._resource,journal,signer,actors=old._actors)
        route=self.prefix_publisher.bind_allocation(self.prefix_owner)
        self.route=self.card_publisher.bind(self.card_owner,allocation_route=route)

    async def test_tls_prefix_counter_and_card_lost_ack_restart_keep_original_results(self):
        original=await self.allocation()
        actual=self.prefix_publisher.jetstream.publish
        counter_subject='$KV.am_board.'+self.rid+'.seq.SH'
        async def lost_counter(subject,*args,**kwargs):
            result=await actual(subject,*args,**kwargs)
            if subject==counter_subject:raise TimeoutError('Controlled loss after actual counter acknowledgement')
            return result
        with patch.object(self.prefix_publisher.jetstream,'publish',side_effect=lost_counter):
            with self.assertRaisesRegex(ContractError,'^board_allocation_outcome_uncertain$'):
                await self.prefix_owner.apply(original)
        counter=await self.kv.get(self.rid+'.seq.SH')
        self.assertEqual(counter.value,b'2')
        with self.assertRaisesRegex(ContractError,'^board_allocation_pending$'):
            await self.prefix_owner._journal.check_card('SH-2')
        with self.assertRaisesRegex(ContractError,'^board_allocation_busy$'):
            await self.prefix_owner.apply(await self.allocation())
        await self.restart_prefix_backend()
        first=await self.prefix_owner.apply(original)
        self.assertEqual((first['key'],first['cardRef']['revision']),
            ('SH-2',(await self.kv.get(self.rid+'.card.SH-2')).revision))
        self.assertEqual((await self.kv.get(self.rid+'.seq.SH')).revision,counter.revision)
        later=await self.allocation()
        async def lost_card(subject,*args,**kwargs):
            result=await actual(subject,*args,**kwargs)
            if subject=='$KV.am_board.'+self.rid+'.card.SH-3':
                raise TimeoutError('Controlled loss after actual card acknowledgement')
            return result
        with patch.object(self.prefix_publisher.jetstream,'publish',side_effect=lost_card):
            with self.assertRaisesRegex(ContractError,'^board_allocation_outcome_uncertain$'):
                await self.prefix_owner.apply(later)
        card=await self.kv.get(self.rid+'.card.SH-3')
        counter=await self.kv.get(self.rid+'.seq.SH')
        await self.restart_prefix_backend()
        recovered=await self.prefix_owner.reconcile(await self.allocation_query(later))
        self.assertEqual(recovered['cardRef']['revision'],card.revision)
        self.assertEqual((await self.kv.get(self.rid+'.seq.SH')).revision,counter.revision)
        old=await self.prefix_owner.reconcile(await self.allocation_query(original))
        self.assertEqual((old['cardRef'],old['receiptRef']),(first['cardRef'],first['receiptRef']))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')),2)
        self.success=True

    async def pending_first_card(self):
        original=await self.allocation()
        actual=self.prefix_publisher.jetstream.publish
        subject='$KV.am_board.'+self.rid+'.card.SH-2'
        async def no_ack(selected,*args,**kwargs):
            if selected==subject:raise TimeoutError('Controlled loss before first-card publication')
            return await actual(selected,*args,**kwargs)
        with patch.object(self.prefix_publisher.jetstream,'publish',side_effect=no_ack):
            with self.assertRaisesRegex(ContractError,'^board_allocation_outcome_uncertain$'):
                await self.prefix_owner.apply(original)
        return original,subject

    async def test_tls_prefix_tombstone_fence_blocks_late_first_card_cas(self):
        original,subject=await self.pending_first_card()
        pending=await self.prefix_owner._journal.pending()
        candidate=base64.b64decode(pending['state']['plan']['candidateBytes'])
        await self.restart_prefix_backend()
        result=await self.prefix_owner.reconcile(await self.allocation_query(original))
        self.assertEqual(result['outcome'],'rejected')
        self.assertIsNone(result['cardRef'])
        head=await self.admin.jetstream().get_msg('KV_am_board',subject=subject,direct=False)
        self.assertEqual((head.data,head.headers['KV-Operation']),(None,'DEL'))
        self.assertIn('Agentmux-Board-Fence',head.headers)
        self.assertNotIn('Nats-Rollup',head.headers)
        with self.assertRaises(APIError):
            await self.prefix_publisher.jetstream.publish(subject,candidate,headers={
                'Nats-Expected-Stream':'KV_am_board','Nats-Expected-Last-Subject-Sequence':'0'})
        self.assertEqual((await self.admin.jetstream().get_msg('KV_am_board',subject=subject,direct=False)).seq,head.seq)
        self.assertEqual(self.store.q('SELECT * FROM fed_audit'),[])
        self.success=True

    async def test_tls_foreign_tombstone_keeps_unresolved_prefix_evidence(self):
        original,subject=await self.pending_first_card()
        await self.admin.jetstream().publish(subject,b'',headers={'Nats-Expected-Stream':'KV_am_board',
            'Nats-Expected-Last-Subject-Sequence':'0','KV-Operation':'DEL'})
        head=await self.admin.jetstream().get_msg('KV_am_board',subject=subject,direct=False)
        await self.restart_prefix_backend()
        with self.assertRaisesRegex(ContractError,'^board_allocation_outcome_uncertain$'):
            await self.prefix_owner.reconcile(await self.allocation_query(original))
        self.assertIsNotNone(await self.prefix_owner._journal.pending())
        self.assertEqual((await self.admin.jetstream().get_msg('KV_am_board',subject=subject,direct=False)).seq,head.seq)
        self.assertEqual(self.store.q('SELECT * FROM fed_audit'),[])
        self.success=True

    async def test_tls_card_write_reconcile_and_prefix_allocation(self):
        inner=await self.admit('capability-storage-write',{'resourceRef':{**ref('task-one'),'revision':self.card_revision},
            'input':{'value':{'command':'comment','text':'ghp_'+'a'*36}}})
        request=await self.prepare(inner)
        result=await self.call(request)
        self.assertEqual(result['outcome'],'applied')
        written=await self.kv.get(self.rid+'.card.SH-1')
        self.assertEqual(result['resourceRef']['revision'],written.revision)
        card=strict_loads(written.value)
        self.assertEqual(card['unknownFutureField'],self.initial_card['unknownFutureField'])
        self.assertNotIn('ghp_',written.value.decode())
        self.assertEqual((await self.call(await self.query(request)))['resourceRef'],result['resourceRef'])
        counter=await self.kv.get(self.rid+'.seq.SH')
        original=await self.admit('federation-board-command',{'resourceRef':{**ref('prefix-one'),'revision':counter.revision},
            'attribution':'operator','input':{'command':'add','title':'Allocated card'}},grant='allocation-command')
        allocated=await self.prefix_owner.apply(original)
        created=await self.kv.get(self.rid+'.card.SH-2')
        self.assertEqual(allocated['cardRef']['revision'],created.revision)
        self.assertEqual((await self.kv.get(self.rid+'.seq.SH')).value,b'2')
        query=await self.admit('capability-outcome-query',{'resourceRef':{**ref('prefix-one'),'revision':counter.revision},
            'input':{'contractId':'federation-board-command',**{key:strict_loads(original)['operation'][key]
                for key in ('operationId','payloadDigest')}}},grant='allocation-query')
        recovered=await self.prefix_owner.reconcile(query)
        self.assertEqual(recovered['cardRef'],allocated['cardRef'])
        self.assertEqual(recovered['receiptRef'],allocated['receiptRef'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')),2)
        self.success=True

    async def test_tls_actual_card_commit_with_lost_reply_is_reconciled_without_another_write(self):
        inner=await self.admit('capability-storage-write',{'resourceRef':{**ref('task-one'),'revision':self.card_revision},
            'input':{'value':{'command':'comment','text':'Exactly once'}}})
        actual=self.card_publisher.jetstream.publish
        writes=[]
        async def lost(subject,*args,**kwargs):
            result=await actual(subject,*args,**kwargs)
            if subject=='$KV.am_board.'+self.rid+'.card.SH-1':
                writes.append(result.seq)
                raise TimeoutError('Controlled loss after actual broker acknowledgement')
            return result
        request=await self.prepare(inner)
        with patch.object(self.card_publisher.jetstream,'publish',side_effect=lost):
            await self.call(request,expect_reply=False)
        committed=await self.kv.get(self.rid+'.card.SH-1')
        result=await self.call(await self.query(request))
        self.assertEqual(result['resourceRef']['revision'],committed.revision)
        self.assertEqual(writes,[committed.revision])
        self.assertEqual([item['text'] for item in strict_loads(committed.value)['comments']],['Exactly once'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')),1)
        self.success=True

    async def denied_publish(self,role,subject,*,headers=None,subscribe=False):
        if role in ('card','prefix'):connection=getattr(self,role+'_publisher')._connection
        elif role=='storage':connection=self.storage
        elif role=='host':connection=self.host
        else:connection=self.attacker
        errors=[]
        event=asyncio.Event()
        original=connection._error_cb
        async def received(error):
            errors.append('permission' if 'permissions violation' in str(error).lower() else 'other')
            event.set()
        connection._error_cb=received
        subscription=None
        try:
            if subscribe:subscription=await connection.subscribe(subject)
            else:await connection.publish(subject,b'{}',headers=headers)
            await connection.flush(timeout=2)
            try:
                async with asyncio.timeout(1):
                    while 'permission' not in errors:
                        event.clear()
                        if 'permission' not in errors:await event.wait()
            except TimeoutError:
                self.fail('Broker permission refusal was not observed: '+role+' '+subject)
        finally:
            if subscription is not None:await subscription.unsubscribe()
            connection._error_cb=original

    async def test_tls_raw_management_and_out_of_scope_kv_delete_purge_are_denied(self):
        before=await self.kv.get(self.rid+'.card.SH-1')
        self.attacker=await self.connect('other-scope')
        for role in ('card','prefix','storage','host','other-scope'):
            for subject in ('$JS.API.STREAM.CREATE.KV_am_board','$JS.API.STREAM.UPDATE.KV_am_board',
                    '$JS.API.STREAM.DELETE.KV_am_board','$JS.API.STREAM.PURGE.KV_am_board',
                    '$JS.API.STREAM.MSG.DELETE.KV_am_board',self.subjects['IDENTITY']):
                await self.denied_publish(role,subject)
            if role!='host':
                for subject in ('$JS.API.STREAM.INFO.IDENTITY','$JS.API.STREAM.MSG.GET.IDENTITY'):
                    await self.denied_publish(role,subject)
            for headers in ({'KV-Operation':'DEL'},{'KV-Operation':'PURGE','Nats-Rollup':'sub'}):
                await self.denied_publish(role,'$KV.am_board.rffffffffffff.card.SH-1',headers=headers)
                await self.denied_publish(role,'$KV.am_board.rffffffffffff.seq.SH',headers=headers)
            for subject in ('$KV.am_board.>','$JS.API.>',
                    'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.federation-board-operations.>'):
                await self.denied_publish(role,subject,subscribe=True)
        for role in ('storage','host','other-scope'):
            for subject in (self.subjects['DATA'],self.subjects['OTHER'],'$KV.am_board.'+self.rid+'.seq.SH'):
                await self.denied_publish(role,subject)
            for headers in ({'KV-Operation':'DEL'},{'KV-Operation':'PURGE','Nats-Rollup':'sub'}):
                await self.denied_publish(role,'$KV.am_board.'+self.rid+'.card.SH-1',headers=headers)
        await self.denied_publish('card',self.subjects['OTHER'])
        await self.denied_publish('prefix',self.subjects['DATA'])
        await self.denied_publish('card','$KV.am_board.'+self.rid+'.card.SH-999')
        for role in ('card','prefix'):
            await self.denied_publish(role,'$KV.am_board.'+self.rid+'.seq.OTHER')
        # The protected host intentionally reads its enrolled authority for key
        # verification. Keep this exact read separate from raw write refusals.
        self.assertEqual((await self.host.jetstream().stream_info('IDENTITY')).config.name,'IDENTITY')
        identity=await self.host.jetstream().get_msg('IDENTITY',subject=self.subjects['IDENTITY'],direct=False)
        self.assertEqual(strict_loads(identity.data)['ownerDomain'],'identity')
        after=await self.kv.get(self.rid+'.card.SH-1')
        self.assertEqual((after.value,after.revision),(before.value,before.revision))
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages,0)
        self.assertEqual((await self.admin.jetstream().stream_info('OTHER')).state.messages,0)
        self.success=True

    async def test_tls_stale_version_revoked_native_parent_and_closed_publisher_refuse_without_effect(self):
        stale=await self.admit('capability-storage-write',{'resourceRef':ref('task-one'),
            'input':{'value':{'command':'comment','text':'Stale version'}}})
        result=await self.call(await self.prepare(stale))
        self.assertEqual((result['outcome'],result['resourceRef']['revision']),('conflict',self.card_revision))
        before=(await self.admin.jetstream().stream_info('DATA')).state.messages
        inner=await self.admit('capability-storage-write',{'resourceRef':{**ref('task-one'),'revision':self.card_revision},
            'input':{'value':{'command':'comment','text':'Must not be written'}}})
        wrapped=await self.prepare(inner)
        await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one','targetRef':ref('parent-row')})
        with self.assertRaisesRegex(ContractError,'^native_parent_binding_invalid$'):
            evaluate_capability_service_request(await self.identity.reader.current(),wrapped,
                service_id='storage-owner',now=datetime.now(timezone.utc))
        await self.call(wrapped,expect_reply=False)
        await self.card_publisher.close()
        with self.assertRaises(ContractError):self.route.check(self.identity.reader,self.card_resource,self.storage)
        card=await self.kv.get(self.rid+'.card.SH-1')
        self.assertEqual((card.value,card.revision),(canonical_bytes(self.initial_card),self.card_revision))
        self.assertEqual((await self.admin.jetstream().stream_info('DATA')).state.messages,before)
        self.success=True

    async def _cleanup(self):
        for responder in reversed(self.responders):await responder.close()
        # Card workers still consult the prefix gate while joining.
        for publisher in reversed(self.publishers):await publisher.close()
        if self.identity is not None:await asyncio.wait_for(self.identity.close(),10)
        for history in self.histories:history.close()
        for connection in reversed(self.connections):await connection.close()
        if self.store is not None:self.store.db.close()
        if self.broker is not None:self.broker.stop()
        if self.success and not self.keep_directory:shutil.rmtree(self.directory)

    async def cleanup(self):
        if not hasattr(self,'_cleanup_work'):self._cleanup_work=asyncio.create_task(self._cleanup())
        await asyncio.shield(self._cleanup_work)
