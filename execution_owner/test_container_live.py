"""Real native Docker task isolation with actual signed A/B owner interfaces."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import ipaddress
import re
import ssl
import subprocess
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from nacl.signing import SigningKey
from unittest.mock import patch
from hub.store import Store, APP_ID, MIGRATIONS
from hub.fed.policy import rid_for_remote
from capability_owner.workspace_host import WorkspaceCheckoutHost
from identity.test_authority import ref, SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED, record
from state_owner.task import TaskOwner
from . import test_container as support
from .test_plans import approved_profile
from .plans import ExecutionPlanOwner
from .container import TaskContainerAdapter, RetainedContainerIntent
from .docker_engine import DockerEngine, DockerSelection
from .network import HTTPSDestination, SelectedNetwork


IMAGE='python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258'

def stamp(value):return value.isoformat().replace('+00:00','Z')


class NativeContainerTests(support.ContainerTests):
    live=True

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_EXECUTION_DOCKER_LIVE')!='1':raise RuntimeError('A coordinated Docker slot is required')
        if platform.system()!='Darwin' or platform.machine()!='arm64':raise RuntimeError('Native macOS ARM64 is required')

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.native_adapters=[]
        import sys
        print('Owned native fixture directory: '+str(self.path),file=sys.stderr)
        environment=patch.dict(os.environ,{'AMX_OUTSIDE_VALUE':'owned-host-fixture'})
        environment.start();self.addCleanup(environment.stop)
        # Do not remove a still-mounted source if owned cleanup is unresolved.
        self._cleanups=[item for item in self._cleanups if not (
            getattr(item[0],'__self__',None) is self.directory and getattr(item[0],'__name__','')=='cleanup')]
        def directory_cleanup():
            runs=[run for adapter in self.native_adapters for run in adapter._runs.values()]
            removed={run.get('id') for run in runs if run.get('removed')}
            unresolved=[run for run in runs if not run.get('removed') and run.get('id') not in removed]
            result=self._outcome.result
            failed=any(case is self for case,_ in [*result.errors,*result.failures])
            if unresolved or failed:
                self.directory._finalizer.detach()
                metadata=[{'name':run['spec']['name'],'containerId':run.get('id'),
                    'runRef':strict_loads(run['binding'])['runRef']} for run in unresolved]
                path=self.path/'owned-container-recovery.private.json'
                path.write_bytes(canonical_bytes(metadata));path.chmod(0o600)
            else:self.directory.cleanup()
        self._cleanups.insert(0,(directory_cleanup,(),{}))

    def native_ledger(self,domain,entity,kind,scope):
        binding=OwnerBinding('hub-one',domain,entity,kind,canonical_bytes(scope))
        js=FakeJetStream(self.policy);js.config.subjects=[owner_subject(binding)]
        return OwnerLedger(js,stream='OWNER',subject=owner_subject(binding),binding=binding,
            retention=self.policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)

    async def signed(self,contract,payload,*,actor,transport,grant,operation,expected,reservation=None):
        now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':transport,'grantRef':grant,'operationId':operation,
            'expectedVersion':expected,'contractId':contract,'payload':payload,'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
            'signature':sign_claims(claims,bytes(reversed(SEED)))})
        admitted=await self.service.ingress.admit(raw,cancellation_ref=ref(operation+'-cancel'),
            reservation_context=reservation)
        self.assertEqual(admitted.decision.outcome,'allowed')
        self.assertEqual(strict_loads(admitted.envelope)['operation']['effectiveActorRef'],actor)
        return raw,admitted.envelope

    async def workspace(self,name):
        directory=self.path/name;directory.mkdir(mode=0o700)
        remote='https://example.invalid/'+name+'.git'
        for args in (('init','-q'),('remote','add','origin',remote)):
            process=await asyncio.create_subprocess_exec('/usr/bin/git','-C',str(directory),*args,
                stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
            self.assertEqual(await process.wait(),0)
        db=self.path/(name+'.sqlite');store=Store(str(db));store.repo_add(name,paths=[str(directory)]);store.db.close();db.chmod(0o600)
        policy=self.path/(name+'.toml');raw=('[federation]\npeer="nick"\n[repos.'+name+']\nremote="example.invalid/'+name+'"\n').encode()
        policy.write_bytes(raw);policy.chmod(0o600)
        host=WorkspaceCheckoutHost({'database':{'path':str(db),'applicationId':APP_ID,'userVersion':len(MIGRATIONS)},
            'policy':{'path':str(policy),'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}},
            repository={'localName':name,'repositoryId':rid_for_remote(remote),'normalizedRemote':'example.invalid/'+name},
            local_peer='nick',checkout_path=str(directory),owner_uid=os.getuid())
        self.addAsyncCleanup(host.close);await host.start()
        return host

    async def case(self,name,workspace,port,roots,script):
        compile(script,'approved-native-probe','exec')
        scope={'organizationId':'org-one','projectId':name,'workspaceId':None}
        actor=ref(name+'-human');worker=ref(name+'-worker');consumer=ref(name+'-consumer');admin=ref('administrator')
        state=self.record['state'];now=datetime.now(timezone.utc)
        interval={'issuedAt':stamp(now-timedelta(seconds=1)),'expiresAt':stamp(now+timedelta(minutes=5)),'status':'active'}
        for identity,kind in ((actor,'human'),(worker,'service'),(consumer,'service')):
            state['identities'].append({'ref':identity,'principalId':identity['id'],'kind':kind,'status':'active','externalIdentity':None})
        for identity in (actor,worker,consumer,admin):
            state['memberships'].append({'ref':ref(name+'-'+identity['id']+'-member'),'identityRef':identity,
                'scope':scope,'status':'active'})
        transport=ref(name+'-transport');state['transports'].append({**copy.deepcopy(state['transports'][0]),
            'ref':transport,'identityRef':actor})
        task_id=name+'-task';plan_ref=ref(name+'-plan');executor=ref(name+'-executor')
        grants={}
        for contract,identity,resource in (('task-inspect',actor,task_id),('task-reserve',actor,task_id),
                ('execution-plan-enroll',admin,plan_ref['id']),('task-inspect',admin,task_id),
                ('capability-process-start',actor,executor['id'])):
            key=(contract,identity['id']);grant=ref(name+'-'+identity['id']+'-'+contract)
            grants[key]=grant
            state['grants'].append({'ref':grant,'callerRef':identity,'actorRef':identity,'scope':scope,
                'contractId':contract,'resourceId':resource,'decision':'allowed','delegationRef':None,
                'definitionTarget':None,**interval})
        self.sync()
        task_ledger=self.native_ledger('task',task_id,'task',scope)
        initial=record(name+'-import');initial.update(entityId=task_id,effects=[],state={'taskId':task_id,
            'status':'ready','assignmentEpoch':0,'reservation':None,'originHubId':'hub-one',
            'taskInputRef':ref(name+'-input'),'flags':{}})
        initial['operation'].update(scope=scope,expectedVersion=0)
        await task_ledger.append(initial,expected_sequence=0,completion_records=0)
        task=TaskOwner(self.service.reader,task_ledger)
        operation=name+'-reserve';refs=task.reservation_references(operation)
        payload={'taskId':task_id,'delegationId':refs['delegationRef']['id'],'attemptId':name+'-attempt',
            'executorHubId':'hub-one','grantRef':refs['executionGrantRef'],'repositoryRevision':'approved-source',
            'assignmentEpoch':1}
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':transport,'grantRef':grants[('task-reserve',actor['id'])],
            'operationId':operation,'expectedVersion':1,'contractId':'task-reserve','payload':payload,
            'approvalRefs':[],'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,bytes(reversed(SEED)))})
        prepared=await task.prepare_reservation(raw,ref(operation+'-cancel'))
        admitted=await self.service.ingress.admit(raw,cancellation_ref=ref(operation+'-cancel'),reservation_context=prepared)
        retained=await task.handle(admitted.envelope,reservation_context=prepared)
        reserved=strict_loads(retained.record)['state']
        profile=approved_profile(scope);profile.update(image=IMAGE,workspaceRef=ref(name+'-workspace'),
            workerIdentityRef=worker,consumerRef=consumer,credentialRef=ref(name+'-credential'))
        profile['isolation']['workerUID']=os.getuid();profile['limits'].update(offlineSeconds=30,maxSeconds=30)
        profile['recipe']={'kind':'python-script-v1','path':'main.py','sha256':'sha256:'+hashlib.sha256(script).hexdigest()}
        profile['network']={'profileRef':ref(name+'-network'),'mode':'none' if port is None else 'scoped-egress',
            'destinationRefs':[] if port is None else [ref(name+'-destination')]}
        (Path(workspace._path)/'main.py').write_bytes(script)
        plans=ExecutionPlanOwner(self.service.reader,self.native_ledger('execution-plans',plan_ref['id'],'approved-execution-plan',scope),
            task,self.service.ingress,executor_ref=executor,enrollment_identity_ref=admin,profile=profile)
        self.addAsyncCleanup(plans.close)
        plan={'schemaVersion':'1.0.0','ref':plan_ref,'executorRef':executor,'profileId':'profile-one','scope':scope,
            'callerIdentityRef':actor,'taskRef':{**ref(task_id),'revision':retained.sequence},'taskInputRef':reserved['taskInputRef'],
            'delegationRef':reserved['delegation']['ref'],'executionGrantRef':reserved['executionGrant']['ref'],
            'attemptId':name+'-attempt','assignmentEpoch':1,'repositoryRevision':'approved-source','profile':profile,
            'issuedAt':stamp(now-timedelta(seconds=1)),'expiresAt':stamp(now+timedelta(seconds=60))}
        async def inspection():
            return (await self.signed('task-inspect',{'taskId':task_id},actor=admin,transport=ref('administrator-transport'),
                grant=grants[('task-inspect',admin['id'])],operation=name+'-inspect',expected=0))[1]
        _,enroll=await self.signed('execution-plan-enroll',{'plan':plan,'previousRef':None},actor=admin,
            transport=ref('administrator-transport'),grant=grants[('execution-plan-enroll',admin['id'])],
            operation=name+'-enroll',expected=0)
        await plans.handle(enroll,task_inspection=await inspection())
        _,start=await self.signed('capability-process-start',{'resourceRef':executor,'input':{'planRef':plan_ref}},
            actor=actor,transport=transport,grant=grants[('capability-process-start',actor['id'])],operation=name+'-start',expected=1)
        admission=await plans.admit_start(start,task_inspection=await inspection())
        binding=strict_loads(admission.binding);original=binding['originalOperation']
        intent_ledger=self.native_ledger('execution',binding['runRef']['id'],'attempt',scope)
        value=record(name+'-intent');value.update(entityId=binding['runRef']['id'],entityKind='attempt',ownerDomain='execution',
            operation=original,state={'executionBinding':binding,'executionPhase':'start-intent'},
            effects=[{'effectId':'container-'+binding['runRef']['id'].removeprefix('execution-'),
                'contractId':'execution-container-prepare','payloadDigest':payload_digest(binding),'grantRef':original['grantRef'],
                'recovery':'query-before-retry','payload':binding}],authorizationDecision={'operationId':original['operationId'],
                'decision':'allowed','reason':'authorized','actorRef':original['effectiveActorRef'],'contractId':'capability-process-start'})
        await intent_ledger.append(value,expected_sequence=0,expected_target_version=1,completion_records=0)
        intent=RetainedContainerIntent(intent_ledger,admission.binding)
        destinations=() if port is None else (HTTPSDestination(canonical_bytes(ref(name+'-destination')),
            'execution.agentmux.invalid','127.0.0.1',port,'/task',roots),)
        adapter=TaskContainerAdapter(plans,self.real_engine,workspace,workspace_ref=profile['workspaceRef'],
            network=SelectedNetwork(profile['network']['profileRef'],destinations))
        self.native_adapters.append(adapter)
        self.addAsyncCleanup(adapter.close)
        return {'adapter':adapter,'admission':admission,'intent':intent,'inspect':inspection,'profile':profile}

    async def test_native_two_users_projects_network_private_channel_and_cleanup(self):
        self.assertEqual(os.getuid(),501)
        # All Docker effects are through this selected adapter; fixture authority
        # uses real signed owners over the already qualified offline ledger boundary.
        self.real_engine=DockerEngine(DockerSelection(str(Path('/Users/ryan/.docker/bin/docker').resolve()),
            'desktop-linux','unix:///Users/ryan/.docker/run/docker.sock','bf61e5bf-20ff-4b43-a588-d6c46ed9e664',
            '29.8.2',str(Path.home()/'.docker'),IMAGE.split('@')[1]))
        config=self.path/'tls.conf';config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=execution.agentmux.invalid\n[v3]\nsubjectAltName=DNS:execution.agentmux.invalid\nbasicConstraints=critical,CA:TRUE\n')
        cert=self.path/'tls.pem';key=self.path/'tls.key'
        with (self.path/'tls.private.log').open('wb') as log:
            process=await asyncio.create_subprocess_exec('/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert),stdout=log,stderr=log)
            self.assertEqual(await process.wait(),0)
        key.chmod(0o600)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
        hits=[]
        async def serve(reader,writer):
            try:
                header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),2)
                hits.append(header.split(b'\r\n',1)[0])
                body=b'approved-network-reply'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                await writer.drain()
            finally:
                writer.close();await writer.wait_closed()
        server=await asyncio.start_server(serve,'0.0.0.0',0,ssl=tls)
        self.addAsyncCleanup(server.wait_closed);self.addCleanup(server.close)
        port=server.sockets[0].getsockname()[1]
        # Probe the actual host interface with the controlled listener, not
        # merely the task's different loopback namespace.
        route=await asyncio.create_subprocess_exec('/sbin/route','-n','get','default',
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        route_output,_=await route.communicate();self.assertEqual(route.returncode,0)
        match=re.search(rb'interface:\s*([A-Za-z0-9]+)',route_output);self.assertIsNotNone(match)
        address=await asyncio.create_subprocess_exec('/usr/sbin/ipconfig','getifaddr',match.group(1).decode(),
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        address_output,_=await address.communicate();self.assertEqual(address.returncode,0)
        host_address=str(ipaddress.IPv4Address(address_output.decode().strip()))
        first=await self.workspace('projectalpha');second=await self.workspace('projectbeta')
        foreign=self.path/'host-canary';foreign.write_text('owned-host-canary')
        for host,other in ((first,second),(second,first)):
            (Path(host._path)/'foreign-link').symlink_to(Path(other._path)/'private-canary')
            (Path(host._path)/'private-canary').write_text('foreign-project-private')
        cases=[]
        for name,host in (('projectalpha',first),('projectbeta',second)):
            script=(r'''
import base64,ctypes,json,os,pathlib,socket
pathlib.Path('/workspace/probe-stage').write_text('entered')
pathlib.Path('/workspace/probe-stage').write_text('uid')
assert os.getuid()==501
pathlib.Path('/workspace/probe-stage').write_text('interfaces')
try:
    interface_names=[name for _,name in socket.if_nameindex()]
    interface_error='none'
except BaseException as error:
    interface_names=[]
    interface_error=type(error).__name__ if type(error).__name__ in ('OSError','AttributeError','PermissionError') else 'other'
import fcntl,struct
observed_interfaces=[]
for interface in interface_names:
    flags=int(pathlib.Path('/sys/class/net',interface,'flags').read_text().strip(),16)
    address=None
    probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:address=socket.inet_ntoa(fcntl.ioctl(probe.fileno(),0x8915,struct.pack('256s',interface.encode()[:15]))[20:24])
    except OSError:pass
    finally:probe.close()
    observed_interfaces.append({'name':interface,'flags':flags,'address':address,
        'operstate':pathlib.Path('/sys/class/net',interface,'operstate').read_text().strip()})
route_rows=[row.split() for row in pathlib.Path('/proc/net/route').read_text().splitlines()[1:] if row.split()]
connected=False
probe=socket.socket();probe.settimeout(.3)
try:probe.connect((HOST_ADDRESS,PORT));connected=True
except OSError:pass
finally:probe.close()
pathlib.Path('/workspace/network-observation.json').write_text(json.dumps({'interfaces':observed_interfaces,
    'interfaceError':interface_error,'routes':route_rows,'hostConnected':connected}))
assert interface_error=='none'
assert {row['name'] for row in observed_interfaces if row['flags'] & 1}=={'lo'}
assert all(row['address'] is None and row['operstate']=='down' for row in observed_interfaces if row['name']!='lo')
assert route_rows==[] and not connected
assert all(row.split()[-1]=='lo' for row in pathlib.Path('/proc/net/if_inet6').read_text().splitlines())
pathlib.Path('/workspace/probe-stage').write_text('routes')
assert all(row.split()[1]!='00000000' for row in pathlib.Path('/proc/net/route').read_text().splitlines()[1:])
pathlib.Path('/workspace/probe-stage').write_text('process')
ctypes.CDLL(None).prctl(15,NAME,0,0,0)
pathlib.Path('/workspace/probe-stage').write_text('ready')
pathlib.Path('/workspace/ready').write_text('ready')
import time
while not pathlib.Path('/workspace/probe').exists():time.sleep(.02)
pathlib.Path('/workspace/probe-stage').write_text('pid')
foreign_pid=pathlib.Path('/workspace/foreign.pid').read_text().strip()
assert not pathlib.Path('/proc/'+foreign_pid+'/comm').exists()
try:os.kill(int(foreign_pid),0);raise AssertionError('foreign process visible')
except (ProcessLookupError,PermissionError):pass
pathlib.Path('/workspace/probe-stage').write_text('privileges')
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert status['NoNewPrivs'].strip()=='1' and int(status['CapEff'].strip(),16)==0
assert status['Seccomp'].strip()=='2'
pathlib.Path('/workspace/probe-stage').write_text('rootfs')
mounts=[line.split() for line in pathlib.Path('/proc/mounts').read_text().splitlines()]
assert any(row[1]=='/' and 'ro' in row[3].split(',') for row in mounts)
pathlib.Path('/workspace/probe-stage').write_text('resources')
quota,period=map(int,pathlib.Path('/sys/fs/cgroup/cpu.max').read_text().split())
assert quota==period
assert pathlib.Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()=='0'
pathlib.Path('/workspace/probe-stage').write_text('root-user')
try:os.setuid(0);raise AssertionError('root allowed')
except PermissionError:pass
assert not os.path.exists('/var/run/docker.sock')
assert not os.path.exists(HOST_CANARY)
assert not os.path.exists('/workspace/foreign-link')
assert os.getenv('AMX_OUTSIDE_VALUE') is None
assert pathlib.Path('/sys/fs/cgroup/memory.max').read_text().strip()=='67108864'
assert pathlib.Path('/sys/fs/cgroup/pids.max').read_text().strip()=='32'
pathlib.Path('/workspace/probe-stage').write_text('private')
assert pathlib.Path('/run/agentmux/credential').read_bytes()==MARKER
for address in ('127.0.0.1',HOST_ADDRESS):
    s=socket.socket();s.settimeout(.3)
    try:s.connect((address,PORT));raise AssertionError('direct host route allowed')
    except OSError:pass
    finally:s.close()
def network(ref):
    c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(4);c.connect('/run/agentmux/network')
    c.sendall(json.dumps({'destinationRef':ref}).encode()+b'\n');raw=b''
    while not raw.endswith(b'\n'):raw+=c.recv(4096)
    c.close();return json.loads(raw)
pathlib.Path('/workspace/probe-stage').write_text('network')
allowed=network(DESTINATION)
assert allowed['status']=='ok' and base64.b64decode(allowed['bodyBase64'])==b'approved-network-reply'
assert network({'id':'foreign-destination','ownerHubId':'hub-one','revision':1})=={'status':'denied'}
pathlib.Path('/workspace/result.json').write_text(json.dumps({'isolation':True,'network':True,'private':True}))
while not pathlib.Path('/workspace/finish').exists():time.sleep(.02)
'''.replace('NAME',repr(name.encode())).replace('HOST_CANARY',repr(str(foreign))).replace('MARKER',repr((name+'-private-fixture').encode()))
                .replace('HOST_ADDRESS',repr(host_address)).replace('PORT',str(port)).replace('DESTINATION',repr(ref(name+'-destination')))).encode()
            cases.append(await self.case(name,host,port,cert.read_text(),script))
        references=[]
        for name,case in zip(('projectalpha','projectbeta'),cases):
            adapter=case['adapter'];admission=case['admission'];intent=case['intent']
            prepared=await adapter.prepare(admission,task_inspection=await case['inspect'](),intent=intent)
            self.assertEqual(prepared.status,'prepared');reference=strict_loads(prepared.run_ref);references.append(reference)
            with self.assertRaises(ContractError):
                await adapter.deliver_private(reference,admission,task_inspection=await case['inspect'](),intent=intent,
                    worker_ref=ref('foreign-worker'),consumer_ref=case['profile']['consumerRef'],material=b'not-delivered')
            await adapter.deliver_private(reference,admission,task_inspection=await case['inspect'](),intent=intent,
                worker_ref=case['profile']['workerIdentityRef'],consumer_ref=case['profile']['consumerRef'],
                material=(name+'-private-fixture').encode())
            await adapter.start(reference,admission,task_inspection=await case['inspect'](),intent=intent)
        try:
            async with asyncio.timeout(5):
                while not all((Path(host._path)/'ready').exists() for host in (first,second)):await asyncio.sleep(.02)
        except TimeoutError:
            observations=[]
            for case,host,reference in zip(cases,(first,second),references):
                observed=await case['adapter'].observe(reference)
                try:
                    with (Path(host._path)/'probe-stage').open('rb') as source:stage=source.read(33)
                except OSError:stage=b'unknown'
                stage=stage.decode() if stage in (b'entered',b'uid',b'interfaces',b'routes',b'process',b'ready') else 'unknown'
                observations.append((observed.status,observed.exit_code,stage))
            self.fail('Owned task barrier: '+repr(observations))
        physical=[]
        for case in cases:
            run=next(iter(case['adapter']._runs.values()))
            state=(await self.real_engine.inspect(run['id']))['State']
            self.assertIs(state['Running'],True)
            self.assertIs(type(state['Pid']),int);self.assertGreater(state['Pid'],0)
            physical.append(state['Pid'])
        self.assertNotEqual(physical[0],physical[1])
        for host,pid in ((first,physical[1]),(second,physical[0])):
            (Path(host._path)/'foreign.pid').write_text(str(pid))
            (Path(host._path)/'probe').write_text('probe')
        async with asyncio.timeout(10):
            while not all((Path(host._path)/'result.json').exists() for host in (first,second)):await asyncio.sleep(.02)
        for host in (first,second):
            result=json.loads((Path(host._path)/'result.json').read_text())
            self.assertEqual(result,{'isolation':True,'network':True,'private':True})
        # Transfer one exact live original through the native checkpoint seam;
        # this neither implements nor qualifies D's durable business journal.
        first_case=cases[0];old=first_case['adapter']
        self.assertEqual((await old.observe(references[0])).status,'running')
        retained=await old.checkpoint()
        self.assertEqual(len(retained),1);self.assertIsNotNone(retained[0].resource_ref)
        recovered=TaskContainerAdapter(old._plans,self.real_engine,first,workspace_ref=first_case['profile']['workspaceRef'],
            network=old._network)
        self.native_adapters.append(recovered);self.addAsyncCleanup(recovered.close)
        observed=await recovered.recover(first_case['intent'],resource_ref=retained[0].resource_ref)
        self.assertEqual(observed.status,'pending');self.assertEqual(observed.resource_ref,retained[0].resource_ref)
        await old.close()
        self.assertEqual((await recovered.stop(references[0])).status,'terminal')
        self.assertFalse(self.real_engine._jobs)
        await recovered.cleanup(references[0])
        (Path(second._path)/'finish').write_text('finish')
        async with asyncio.timeout(5):
            while (await cases[1]['adapter'].observe(references[1])).status!='terminal':await asyncio.sleep(.02)
        observed=await cases[1]['adapter'].observe(references[1])
        self.assertEqual(observed.exit_code,0)
        await cases[1]['adapter'].cleanup(references[1])
        self.assertEqual(hits,[b'GET /task HTTP/1.1',b'GET /task HTTP/1.1'])
        self.assertEqual(foreign.read_text(),'owned-host-canary')

    async def test_native_lost_create_reply_keeps_one_owned_original(self):
        self.real_engine=DockerEngine(DockerSelection(str(Path('/Users/ryan/.docker/bin/docker').resolve()),
            'desktop-linux','unix:///Users/ryan/.docker/run/docker.sock','bf61e5bf-20ff-4b43-a588-d6c46ed9e664',
            '29.8.2',str(Path.home()/'.docker'),IMAGE.split('@')[1]))
        host=await self.workspace('projectuncertain')
        case=await self.case('projectuncertain',host,None,None,b'import time;time.sleep(1)\n')
        adapter=case['adapter'];admission=case['admission'];intent=case['intent']
        original=self.real_engine._run;creates=[]
        async def lost(args,**kwargs):
            result=await original(args,**kwargs)
            if args[0]=='create':
                creates.append(True)
                raise ContractError('execution_engine_command_unknown')
            return result
        self.real_engine._run=lost
        with self.assertRaisesRegex(ContractError,'^execution_engine_command_unknown$'):
            await adapter.prepare(admission,task_inspection=await case['inspect'](),intent=intent)
        self.real_engine._run=original
        again=await adapter.prepare(admission,task_inspection=await case['inspect'](),intent=intent)
        self.assertEqual(again.status,'pending');self.assertEqual(len(creates),1)
        reference=strict_loads(again.run_ref)
        with self.assertRaises(ContractError):
            await adapter.start(reference,admission,task_inspection=await case['inspect'](),intent=intent)
        self.assertFalse(self.real_engine._jobs)
        await adapter.cleanup(reference)
        self.assertIsNone(await self.real_engine.find(next(iter(adapter._runs.values()))['spec']['name']))


for _name in dir(support.ContainerTests):
    if _name.startswith('test_') and _name not in vars(NativeContainerTests):setattr(NativeContainerTests,_name,None)
