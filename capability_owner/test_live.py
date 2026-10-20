"""Coordinated TLS/NATS qualification of concrete read receivers.

This exercises retained identity and resource ledgers, real issuer preparation,
scoped broker credentials and signed replies. It does not qualify domain writes
or external effects. A separate private-child case checks delegated reads and
parent revocation. The Go child uses the production native TLS transport,
enrolled key source, authority and capability gateway.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import json
import hashlib
import os
from pathlib import Path
import platform
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nats
from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.service import IdentityService, verify_receipt
from identity.native_bridge import verify_response
from identity.test_authority import ref, SEED
from identity.test_commands import command_fixture
from identity.test_native_bridge import HOST_SEED, native_row
from state_owner.artifacts import OwnerArtifacts
from hub.fed.code_services import RepositoryDirectory, GitOperations, CodeSettings
from hub.fed.policy import rid_for_remote
from hub.store import Store
from hub.nats_transport import new_client
from identity.capability_routes import CAPABILITY_DESTINATIONS
from .workspace import WorkspaceRoot
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.history import OwnerHistory
from state_owner.backup_host import BackupHost
from state_owner.test_ledger import record
from tests.storage.run import Broker, SERVER
from .reply_service import CapabilityReplyService, verify_capability_response
from .resources import RetainedResource


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def packet(claims, seed, *, native=False):
    value={'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,seed)}
    if native:
        value.update(algorithm='Ed25519',canonicalization='RFC8785-JCS-UTF8')
    return canonical_bytes(value)


class LiveCapabilityTests(unittest.IsolatedAsyncioTestCase):
    private_child=False
    read_contract="capability-storage-read"
    read_class="storage"
    read_action="read"
    boundary_checks=False

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_CAPABILITY_LIVE') != '1':
            raise RuntimeError('A coordinated capability live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')
        binary=Path(os.environ.get('AMX_CAPABILITY_GO_BINARY',''))
        if not binary.is_absolute() or not binary.is_file():
            raise RuntimeError('A prepared native capability Go test binary is required')

    async def asyncSetUp(self):
        self.directory=Path(tempfile.mkdtemp(prefix='agentmux-capability-live-')).resolve()
        self.connections=[]
        self.go_process=self.go_wait=self.go_output=None
        self.keep_directory=False
        self.success=False
        self.identity=self.receiver=self.broker=None
        self.workspace=self.checkout_store=self.git_executor=None
        self.artifact_ref=None
        self.read_input={}
        self.service_id=CAPABILITY_DESTINATIONS[self.read_contract]
        self.addAsyncCleanup(self.cleanup_owned)
        self.errors={}
        self.permission_events={}
        self.inbox_prefixes={role:'_INBOX.'+secrets.token_hex(16)
            for role in ('provisioner','identity','storage','host','other-scope')}
        self.scope={'organizationId':'org-one','projectId':None,'workspaceId':None}
        self.policy=Retention(4_194_304,524_288)
        self.issuer_public=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        self.service_seed=secrets.token_bytes(32)
        self.service_public=base64.urlsafe_b64encode(bytes(SigningKey(self.service_seed).verify_key)).decode().rstrip('=')
        self.row=native_row()
        self.row['facts']['grant']['actions']=[self.read_action]
        self.row['facts']['policy']['decisions']=[{'access':{
            'action':self.read_action,'resourceClass':self.read_class,'resourceId':'task-one'},'outcome':'allow'}]
        self.row['facts']['domainBindings']=[{'id':'storage-binding','contractId':self.read_contract,
            'action':self.read_action,'resourceClass':self.read_class,'resourceIds':['task-one']}]
        if self.read_contract=='capability-outcome-query':
            self.row['facts']['grant']['actions'].append('write')
            self.row['facts']['policy']['decisions'].append({'access':{
                'action':'write','resourceClass':'storage','resourceId':'task-one'},'outcome':'allow'})
            self.row['facts']['domainBindings'].append({'id':'original-storage-write',
                'contractId':'capability-storage-write','action':'write','resourceClass':'storage',
                'resourceIds':['task-one']})
        self.bindings={
            'IDENTITY':OwnerBinding('hub-one','identity','authority-one','identity-authority',canonical_bytes(self.scope)),
            'DATA':OwnerBinding('hub-one','task','task-one','task',canonical_bytes(self.scope)),
            'OTHER':OwnerBinding('hub-one','task','task-other','task',canonical_bytes({
                'organizationId':'other-org','projectId':None,'workspaceId':None}))}
        self.subjects={name:owner_subject(binding) for name,binding in self.bindings.items()}
        self.identity_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.read_subject='amx.v1.h.hub-one.o.org-one.p._.w._.capability.'+self.service_id+'.command'
        self.other_subject='amx.v1.h.hub-one.o.other-org.p._.w._.capability.storage-owner.command'
        self.broker=Broker(self.directory)
        self._configure_tls_and_users()
        admin=await self.start_tls_broker()
        infos={name:await admin.jetstream().add_stream(self.policy.stream_config(
            stream=name,subject=self.subjects[name])) for name in self.bindings}
        identities={name:StreamIdentity(info.created,0) for name,info in infos.items()}
        metadata=await admin.request('$JS.API.STREAM.INFO.IDENTITY',b'{}',timeout=2)
        # Preserve the broker's full RFC 3339 precision for Go's exact epoch check.
        self.identity_created=strict_loads(metadata.data)['created']
        initial,_=command_fixture()
        initial.update(entityVersion=1,previousRevision=0,effects=[],artifacts=[],repository=None)
        initial['operation'].update(scope=copy.deepcopy(self.scope),expectedVersion=0)
        state=initial['state']
        for name,kind in [('host','service'),('plugin','plugin'),('storage-service','service')]:
            state['identities'].append({'ref':ref(name),'status':'active','kind':kind,
                'principalId':name+'-one','externalIdentity':None})
        if self.private_child:
            state['identities'].append({'ref':ref('parent-plugin'),'status':'active','kind':'plugin',
                'principalId':'parent-one','externalIdentity':None})
        issuer=copy.deepcopy(state['issuers'][0])
        issuer.update(ref=ref('storage-signer'),identityRef=ref('storage-service'),
                      instanceId='storage-one',publicKey=self.service_public)
        state['issuers'].append(issuer)
        host=copy.deepcopy(state['transports'][0])
        host.update(ref=ref('host-transport'),identityRef=ref('host'),publicKey=base64.urlsafe_b64encode(
            bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(host)
        member=copy.deepcopy(state['memberships'][0]);member.update(ref=ref('host-member'),identityRef=ref('host'))
        state['memberships'].append(member)
        base=copy.deepcopy(state['grants'][0])
        grants=[('native-admin','identity-native-instance-set','authority-one'),
                ('storage-read',self.read_contract,'task-one')]
        if self.read_contract=='capability-outcome-query':
            grants.append(('original-write','capability-storage-write','task-one'))
        for name,contract,resource in grants:
            grant=copy.deepcopy(base);grant.update(ref=ref(name),contractId=contract,resourceId=resource)
            state['grants'].append(grant)
        for method in ('bind-instance','admit-operation','recheck','prepare-domain-call'):
            grant=copy.deepcopy(base)
            grant.update(ref=ref('host-'+method),callerRef=ref('host'),actorRef=ref('host'),
                contractId='native-authority-'+method,resourceId='plugin-one')
            state['grants'].append(grant)
            if self.private_child:
                parent_grant=copy.deepcopy(grant)
                parent_grant.update(ref=ref('parent-host-'+method),resourceId='parent-one')
                state['grants'].append(parent_grant)
        now=datetime.now(timezone.utc)
        def current_times(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if key=='issuedAt':value[key]=stamp(now-timedelta(seconds=30))
                    elif key in ('expiresAt','deadline'):value[key]=stamp(now+timedelta(minutes=5))
                    elif key=='recordedAt':value[key]=stamp(now)
                    else:current_times(item)
            elif isinstance(value,list):
                for item in value:current_times(item)
        current_times(initial);current_times(self.row)
        bootstrap=OwnerLedger(admin.jetstream(),stream='IDENTITY',subject=self.subjects['IDENTITY'],
            binding=self.bindings['IDENTITY'],retention=self.policy,stream_identity=identities['IDENTITY'])
        await bootstrap.append(initial,expected_sequence=0)
        identity_connection=await self.connect('identity')
        history=OwnerHistory(self.directory/'identity-history.sqlite',self.bindings['IDENTITY'],
            stream_identity=identities['IDENTITY'])
        backup_directories=[self.directory/name for name in ('identity-backup','identity-inventory','identity-backup-keys')]
        for directory in backup_directories:directory.mkdir(mode=0o700)
        backup=BackupHost(*backup_directories,destination_id='capability-identity-backup',
            binding=self.bindings['IDENTITY'],stream_identity=identities['IDENTITY'])
        backup.enroll_key('capability-backup-one')
        self.checkpoint_receipts=[]
        async def committed(receipt):
            self.checkpoint_receipts.append(receipt)
        self.identity=IdentityService(identity_connection,stream='IDENTITY',stream_identity=identities['IDENTITY'],
            retention=self.policy,hub_id='hub-one',entity_id='authority-one',profile_id='profile-one',
            organization_id='org-one',issuer_ref=ref('issuer'),signing_seed=SEED,
            history=history,checkpoint_path=self.directory/'identity-checkpoint.json',checkpoint_committed=committed,
            backup_host=backup,backup_key_id='capability-backup-one')
        await self.identity.start()
        self.host=await self.connect('host')
        # Certificate, JWT, stream, history and backup setup do not consume the
        # Go child's existing 25-second integration deadline.
        await self.prepare_read_owner(admin)
        await self.start_go_child()
        for row in ([self.parent,self.row] if self.private_child else [self.row]):
            await self.command('identity-native-instance-set',ref('native-admin'),{
                'authorityId':'authority-one','record':row,'previousRef':None})
        for name in ('DATA','OTHER'):
            value=record('retained-'+name.lower())
            value['entityId']=self.bindings[name].entity_id
            value['operation']['scope']=strict_loads(self.bindings[name].scope)
            value['state']['unknownPreservedField']={'value':name}
            if name=='DATA':
                if self.artifact_ref:value['artifacts']=[self.artifact_ref]
                if self.workspace:
                    value['repository']={'repositoryId':self.repository_id,'revision':'fixture-working-tree',
                        'treeDigest':'sha256:'+hashlib.sha256(self.content_bytes).hexdigest()}
                value['authorizationDecision']={'operationId':value['operation']['operationId'],
                    'decision':'allowed','reason':'fixture_retained_history',
                    'actorRef':value['operation']['effectiveActorRef'],'contractId':'capability-storage-write'}
                if self.read_contract=='capability-outcome-query':
                    self.read_input={'contractId':'capability-storage-write',
                        'operationId':value['operation']['operationId'],'payloadDigest':value['operation']['payloadDigest']}
                    self.expected_payload={'operationId':value['operation']['operationId'],
                        'payloadDigest':value['operation']['payloadDigest'],'outcome':'committed',
                        'recordRef':{'id':value['recordId'],'ownerHubId':'hub-one','revision':value['entityVersion']},
                        'contractId':'capability-storage-write','resourceRef':{
                            'id':self.bindings[name].entity_id,'ownerHubId':'hub-one','revision':value['entityVersion']}}
            owner=OwnerLedger(admin.jetstream(),stream=name,subject=self.subjects[name],
                binding=self.bindings[name],retention=self.policy,stream_identity=identities[name])
            await owner.append(value,expected_sequence=0)
            if name=='DATA':self.original=canonical_bytes(value)
        storage=await self.connect('storage')
        artifacts=None
        if self.artifact_ref:
            artifacts=OwnerArtifacts(await storage.jetstream().object_store('CAPABILITY'),storage.jetstream(),
                bucket='CAPABILITY',owner_hub_id='hub-one',store_ref=ref('artifact-store'),max_bytes=45000)
        resource=RetainedResource.open_existing(storage.jetstream(),binding=self.bindings['DATA'],stream='DATA',
            stream_identity=identities['DATA'],retention=self.policy,artifacts=artifacts,workspace=self.workspace)
        self.receiver=CapabilityReplyService(self.identity.reader,resources=[resource],hub_id='hub-one',
            profile_id='profile-one',authority_id='authority-one',service_id=self.service_id,
            service_identity_ref=ref('storage-service'),service_instance_id='storage-one',
            signing_key_ref=ref('storage-signer'),signing_seed=self.service_seed,
            request_signing_key_ref=ref('issuer'),connection=storage)
        await self.receiver.start()
        self.attacker=await self.connect('other-scope')

    async def prepare_read_owner(self,admin):
        self.content_bytes=b'original capability content'
        if self.read_contract=='capability-artifact-read':
            store=await admin.jetstream().create_object_store(bucket='CAPABILITY',max_bytes=1_048_576)
            artifacts=OwnerArtifacts(store,admin.jetstream(),bucket='CAPABILITY',owner_hub_id='hub-one',
                store_ref=ref('artifact-store'),max_bytes=45000)
            self.artifact_ref=await artifacts.upload(self.content_bytes,media_type='text/plain')
            self.read_input={'digest':self.artifact_ref['digest']}
        elif self.read_contract=='capability-workspace-read':
            checkout_path=self.directory/'checkout'
            checkout_path.mkdir(mode=0o700)
            remote='https://fixture.invalid/capability-owner.git'
            for arguments in (('init','-q',str(checkout_path)),
                    ('-C',str(checkout_path),'remote','add','origin',remote)):
                result=subprocess.run(['/usr/bin/git',*arguments],capture_output=True,timeout=5)
                if result.returncode:raise RuntimeError('capability_fixture_checkout_failed')
            (checkout_path/'file').write_bytes(self.content_bytes)
            (checkout_path/'link').symlink_to(checkout_path/'file')
            self.checkout_store=Store(str(self.directory/'checkout.sqlite'))
            self.git_executor=ThreadPoolExecutor(max_workers=1)
            async def db(function,*args):return function(*args)
            owner=SimpleNamespace(store=self.checkout_store,db=db,hub=SimpleNamespace(io=self.git_executor))
            git=GitOperations(owner)
            self.repository_id=rid_for_remote(remote)
            checkout=await RepositoryDirectory(owner,git,CodeSettings('origin')).checkout(
                'fixture-repo',str(checkout_path),self.repository_id)
            self.workspace=WorkspaceRoot(checkout)
            self.read_input={'relativePath':'file'}

    def expected_reply_digest(self):
        if self.read_contract=='capability-storage-read':return ''
        if self.read_contract=='capability-outcome-query':payload=self.expected_payload
        else:payload={'resourceRef':ref('task-one'),'data':base64.b64encode(self.content_bytes).decode()}
        return 'sha256:'+hashlib.sha256(canonical_bytes(payload)).hexdigest()

    def _configure_tls_and_users(self):
        self.server_name=getattr(self,'tls_server_name','capability.agentmux.invalid')
        ca_config=self.directory/'ca.conf'
        ca_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n'
            '[dn]\nCN=Disposable capability CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n'
            'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        leaf_config=self.directory/'leaf.conf'
        leaf_config.write_text('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN='+self.server_name+
            '\n[server]\nsubjectAltName=DNS:'+self.server_name+'\nbasicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
            'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        ca,ca_key=self.directory/'ca.pem',self.directory/'ca.key'
        cert,key=self.directory/'server.pem',self.directory/'server.key'
        csr=self.directory/'server.csr'
        commands=[['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-config',str(ca_config),'-keyout',str(ca_key),'-out',str(ca)],
            ['req','-new','-newkey','rsa:2048','-nodes','-config',str(leaf_config),
             '-keyout',str(key),'-out',str(csr)],
            ['x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial',
             '-days','1','-extfile',str(leaf_config),'-extensions','server','-out',str(cert)]]
        log_descriptor=os.open(self.directory/'certificate.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(log_descriptor,'wb') as log:
            for arguments in commands:
                result=subprocess.run(['/usr/bin/openssl',*arguments],stdout=log,stderr=log,timeout=10)
                if result.returncode:raise RuntimeError('capability_fixture_tls_failed')
        for path in (ca_config,leaf_config,ca,ca_key,cert,key,csr):path.chmod(0o600)
        self.ca_file=ca
        self.leaf_digest='sha256:'+hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        self.tls=ssl.create_default_context(cafile=str(ca))
        self.tls.minimum_version=ssl.TLSVersion.TLSv1_3
        def reads(*names):
            return [subject for name in names for subject in
                ('$JS.API.STREAM.INFO.'+name,'$JS.API.STREAM.MSG.GET.'+name)]
        policies={
            'identity':{'publish':{'allow':[self.subjects['IDENTITY']]+reads('IDENTITY')},
                        'subscribe':{'allow':[self.identity_subject]}},
            'storage':{'publish':{'allow':reads('DATA')},
                       'subscribe':{'allow':[self.read_subject]}},
            'host':{'publish':{'allow':[self.identity_subject,self.read_subject]},'subscribe':{'allow':[]}},
            'other-scope':{'publish':{'allow':[self.other_subject]},'subscribe':{'allow':[]}}}
        if self.read_contract=='capability-artifact-read':
            policies['storage']['publish']['allow'].extend(reads('OBJ_CAPABILITY'))
        configure=getattr(self,'configure_broker_policies',None)
        if configure is not None:
            configure(policies,reads)
        # JetStream request/reply operations require private reply subscriptions.
        inbox_roles = getattr(self, 'private_inbox_roles', policies)
        for role in policies:
            if role in inbox_roles:
                policies[role]['subscribe']['allow'].append(self.inbox_prefixes[role]+'.>')
        # Reuse the native fixture's private nsc operator/account setup. No
        # caller receives provisioner credentials or another role's seed.
        nsc=Path(os.environ.get('AGENTMUX_PLUGIN_NSC',''))
        if not nsc.is_file():raise RuntimeError('prepared capability nsc is required')
        def call(*arguments):
            command=[str(nsc),'--config-dir',str(self.directory/'nsc-config'),
                '--data-dir',str(self.directory/'nsc-store'),'--keystore-dir',str(self.directory/'nsc-keys'),*arguments]
            with (self.directory/'nsc.private.log').open('ab') as log:
                os.chmod(log.name,0o600)
                result=subprocess.run(command,stdout=subprocess.PIPE,stderr=log,timeout=8)
            if result.returncode or len(result.stdout)>65536:
                self.keep_directory=True
                with (self.directory/'nsc.private.log').open('ab') as log:
                    log.write(result.stdout[:65536])
                raise RuntimeError('capability_fixture_nsc_failed')
            return result.stdout
        call('add','operator','--sys','--name','capabilitytest')
        call('add','account','--name','CAPABILITY')
        call('edit','account','--name','CAPABILITY','--js-enable','0')
        call('edit','account','--name','CAPABILITY','--js-disk-storage',getattr(self,'broker_disk_storage','16m'),
            '--js-mem-storage','0','--js-streams',str(getattr(self,'broker_stream_limit',
                4 if self.read_contract=='capability-artifact-read' else 3)),'--js-consumer','0')
        policies['provisioner']={'publish':{'allow':['>']},
            'subscribe':{'allow':[self.inbox_prefixes['provisioner']+'.>']}}
        if self.boundary_checks:
            policies['provisioner']['subscribe']['allow'].extend([
                'amx.v1.h.hub-one.kernel.internal.boot.command',
                'amx.v1.h.hub-one.kernel.reply.capability-probe'])
        # The production host key source reads only this enrolled aggregate.
        policies['host']['publish']['allow'].extend(reads('IDENTITY'))
        self.credentials={}
        for role,permissions in policies.items():
            arguments=['add','user','-a','CAPABILITY','-n',role]
            for subject in permissions['publish']['allow']:arguments.extend(('--allow-pub',subject))
            for subject in permissions['subscribe']['allow']:arguments.extend(('--allow-sub',subject))
            if role in ('identity','storage'):
                arguments.extend(('--allow-pub-response','1','--response-ttl',
                    getattr(self,'response_ttls',{}).get(role,'5s')))
            call(*arguments)
            credentials=call('generate','creds','-a','CAPABILITY','-n',role)
            path=self.directory/(role+'.creds')
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as output:output.write(credentials)
            self.credentials[role]=path
        account=strict_loads(call('describe','account','CAPABILITY','--json'))
        self.account_public_key=account['sub']
        configuration=call('generate','config','--mem-resolver','--sys-account','SYS')
        configuration+=('\nlisten: "127.0.0.1:'+str(self.broker.port)+'"\ntrace: false\n'
            'jetstream { store_dir: '+json.dumps(str(self.directory/'store'))+', sync_interval: always }\n'
            'tls { cert_file: '+json.dumps(str(cert))+', key_file: '+json.dumps(str(key))+
            ', min_version: \"1.3\", handshake_first: true }\n').encode()
        self.broker.config.write_bytes(configuration)
        self.broker.url='tls://127.0.0.1:'+str(self.broker.port)

    async def start_tls_broker(self):
        # Keep the existing Broker's process/log ownership and stop routine;
        # strict TLS-first readiness cannot use its plaintext INFO probe.
        descriptor=os.open(self.directory/'server.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        self.broker.log=os.fdopen(descriptor,'wb')
        self.broker.process=subprocess.Popen([str(SERVER),'-c',str(self.broker.config)],
            stdout=self.broker.log,stderr=self.broker.log)
        deadline=asyncio.get_running_loop().time()+5
        while asyncio.get_running_loop().time()<deadline:
            if self.broker.process.poll() is not None:
                raise RuntimeError('capability_fixture_broker_stopped')
            try:
                return await self.connect('provisioner')
            except (OSError,nats.errors.Error,TimeoutError):
                await asyncio.sleep(.05)
        raise RuntimeError('capability_fixture_broker_not_ready')

    async def connect(self,role):
        errors=[]
        self.errors[role]=errors
        self.permission_events[role]=asyncio.Event()
        async def on_error(error):
            category='permission' if 'permissions violation' in str(error).lower() else 'other'
            errors.append(category)
            if category=='permission':self.permission_events[role].set()
            descriptor=os.open(self.directory/'client.private.log',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(descriptor,'a') as log:
                log.write(type(error).__name__+': '+str(error)[:1000]+'\n')
        connection=new_client()
        self.connections.append(connection)
        await connection.connect(self.broker.url,user_credentials=str(self.credentials[role]),tls=self.tls,
            tls_hostname=self.server_name,tls_handshake_first=True,
            allow_reconnect=False,connect_timeout=2,error_cb=on_error,inbox_prefix=self.inbox_prefixes[role])
        peer=connection._transport._io_writer.get_extra_info('ssl_object')
        self.assertEqual(peer.version(),'TLSv1.3')
        self.assertEqual('sha256:'+hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest(),self.leaf_digest)
        return connection

    async def exchange(self,connection,subject,raw,reply,*,timeout=2):
        sub=await connection.subscribe(reply)
        try:
            await connection.flush(timeout=2)
            await connection.publish(subject,raw,reply=reply)
            return (await sub.next_msg(timeout=timeout)).data
        finally:
            await sub.unsubscribe()

    async def command(self,contract,grant,payload):
        snapshot=await self.identity.ledger.current()
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':ref('transport'),'grantRef':grant,
            'operationId':'command-'+secrets.token_hex(16),'expectedVersion':strict_loads(snapshot.latest.record)['entityVersion'],
            'contractId':contract,'payload':payload,'approvalRefs':[],
            'issuedAt':stamp(datetime.now(timezone.utc)),'expiresAt':stamp(datetime.now(timezone.utc)+timedelta(seconds=4)),
            'replySubject':self.host.new_inbox()}
        raw=packet(claims,bytes(reversed(SEED)))
        response=await self.exchange(self.host,self.identity_subject,raw,claims['replySubject'])
        receipt=verify_receipt(response,raw,public_key=self.issuer_public,issuer_ref=ref('issuer'))
        self.assertEqual(receipt['decision'],'allowed')

    async def native(self,method,inputs,*,timeout=2):
        now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-native-authority-request-v1','requestId':'native-'+secrets.token_hex(16),
            'method':method,'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
            'owner':self.row['owner'],'signingKeyRef':ref('host-transport'),'issuedAt':stamp(now),
            'expiresAt':stamp(now+timedelta(seconds=4)),'replySubject':self.host.new_inbox(),'input':inputs}
        raw=packet(claims,HOST_SEED,native=True)
        response=await self.exchange(self.host,self.identity_subject,raw,claims['replySubject'],timeout=timeout)
        return verify_response(response,raw,public_key=self.issuer_public,signing_key_ref=ref('issuer'),
            now=datetime.now(timezone.utc))['result']

    async def original_envelope(self):
        now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':ref('transport'),'grantRef':ref('storage-read'),
            'operationId':'read-'+secrets.token_hex(16),'expectedVersion':1,
            'contractId':self.read_contract,'payload':{'resourceRef':ref('task-one'),'input':self.read_input},
            'approvalRefs':[],'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=4))}
        admitted=await self.identity.ingress.admit(packet(claims,bytes(reversed(SEED))),cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        return admitted.envelope

    async def prepare(self,reply,*,resource=None):
        original=await self.original_envelope()
        authority=await self.native('admit-operation',{'envelopeBytes':base64.b64encode(original).decode(),
            'audience':{'hubId':'hub-one','serviceId':self.service_id}})
        prepared=await self.native('prepare-domain-call',{'operation':authority['operation'],
            'operationAuthorityRef':authority['authorityRef'],'bindingId':'storage-binding',
            'contractId':self.read_contract,'serviceRequestId':'request_'+secrets.token_hex(32),
            'serviceReplySubject':reply,'payload':{'resourceRef':resource or ref('task-one'),'input':self.read_input},
            'originalEnvelopeBytes':base64.b64encode(original).decode()})
        return base64.b64decode(prepared['serviceRequestBytes'])

    async def read(self,*,change=None,resource=None,received_reply=None,connection=None,expect_reply=True):
        reply=self.host.new_inbox()
        sub=await self.host.subscribe(reply)
        try:
            await self.host.flush(timeout=2)
            raw=await self.prepare(reply,resource=resource)
            if change:
                frame=strict_loads(raw);change(frame['claims'])
                raw=packet(frame['claims'],SEED,native=True)
            await (connection or self.host).publish(self.read_subject,raw,reply=received_reply or reply)
            if not expect_reply:
                with self.assertRaises(nats.errors.TimeoutError):await sub.next_msg(timeout=.25)
                return raw,None
            response=(await sub.next_msg(timeout=2)).data
            payload=verify_capability_response(response,raw,public_key=self.service_public,
                signing_key_ref=ref('storage-signer'),service_identity_ref=ref('storage-service'),
                service_instance_id='storage-one',now=datetime.now(timezone.utc))
            self.assertEqual(base64.b64decode(strict_loads(payload)['data']),self.original)
            return raw,response
        finally:
            await sub.unsubscribe()

    def write_private(self,name,value,*,raw=False):
        descriptor,temporary=tempfile.mkstemp(prefix='.python-handoff-',dir=self.directory)
        try:
            with os.fdopen(descriptor,'wb') as output:
                output.write(value if raw else canonical_bytes(value))
            os.replace(temporary,self.directory/name)
        finally:
            if os.path.exists(temporary):os.unlink(temporary)

    async def wait_handoff(self,name,accept,*,timeout=8):
        deadline=asyncio.get_running_loop().time()+timeout
        while asyncio.get_running_loop().time()<deadline:
            path=self.directory/name
            try:
                descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            except FileNotFoundError:
                pass
            else:
                with os.fdopen(descriptor,'rb') as source:
                    info=os.fstat(source.fileno())
                    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>65536:
                        raise RuntimeError('capability_fixture_handoff_invalid')
                    value=strict_loads(source.read(65537))
                    if accept(value):return value
            if self.go_output is not None and os.fstat(self.go_output.fileno()).st_size>65536:
                self.keep_directory=True
                raise RuntimeError('capability_fixture_go_output_limit')
            if self.go_wait.done():
                self.keep_directory=True
                raise RuntimeError('capability_fixture_go_failed')
            await asyncio.sleep(.02)
        self.keep_directory=True
        raise RuntimeError('capability_fixture_handoff_timeout')

    async def start_go_child(self):
        descriptor=os.open(self.directory/'go.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        self.go_output=os.fdopen(descriptor,'wb')
        environment=dict(os.environ,AMX_NATIVE_CAPABILITY_LIVE_DIR=str(self.directory),
            AMX_NATIVE_CAPABILITY_CLASS=self.read_class,AMX_NATIVE_CAPABILITY_ACTION=self.read_action,
            AMX_NATIVE_CAPABILITY_PRIVATE='1' if self.private_child else '0',
            AMX_NATIVE_CAPABILITY_RECOVERY='1' if getattr(self, 'recovery_checks', False) else '0')
        self.go_process=await asyncio.create_subprocess_exec(os.environ['AMX_CAPABILITY_GO_BINARY'],
            '-test.run=^TestNativeCapabilityTLSIntegration$','-test.count=1','-test.timeout=35s',
            env=environment,stdout=self.go_output,stderr=self.go_output)
        self.go_wait=asyncio.create_task(self.go_process.wait())
        declaration=await self.wait_handoff('go-declaration.json',lambda value:True)
        expected={'owner','manifestDigest','configurationChecksum'}
        if self.private_child:expected.add('parent')
        if not isinstance(declaration,dict) or set(declaration)!=expected:
            raise RuntimeError('capability_fixture_declaration_invalid')
        parent=declaration.pop('parent',None)
        self.row.update(declaration)
        if self.private_child:
            if not isinstance(parent,dict) or set(parent)!={'owner','manifestDigest','configurationChecksum'}:
                raise RuntimeError('capability_fixture_parent_invalid')
            self.parent=copy.deepcopy(self.row)
            self.parent.update(parent)
            self.parent.update(ref=ref('native-parent'),identityRef=ref('parent-plugin'))
            self.parent['facts']['grant'].update(grantId='parent-grant',subjectInstanceId='parent-one')
            self.parent['facts']['policy']['subjectInstanceId']='parent-one'
            self.row.update(relationship='private',parentOwner=copy.deepcopy(self.parent['owner']))
            self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
            self.row['facts']['grant']['parentGrantRef']=ref('parent-grant')
            self.row['facts']['parentAccess']=[{'action':self.read_action,'resourceClass':self.read_class,'resourceId':'task-one'}]
            if self.read_contract=='capability-outcome-query':
                self.row['facts']['parentAccess'].append({'action':'write','resourceClass':'storage','resourceId':'task-one'})

    async def run_go_read_and_revocation(self):
        original=await self.original_envelope()
        self.write_private('host-signing.seed',HOST_SEED,raw=True)
        self.write_private('original-envelope.json',original,raw=True)
        snapshot=await self.identity.ledger.current()
        ready={'serverUrl':self.broker.url,'authoritySubject':self.identity_subject,
            'capabilitySubject':self.read_subject,'credentialsFile':str(self.credentials['host']),
            'caFile':str(self.ca_file),'tlsName':self.server_name,'leafCertificateSha256':self.leaf_digest,
            'accountPublicKey':self.account_public_key,'replyPrefix':self.inbox_prefixes['host'],
            'publishSubjects':[self.identity_subject,self.read_subject,
                '$JS.API.STREAM.INFO.IDENTITY','$JS.API.STREAM.MSG.GET.IDENTITY'],
            'hostSigningSeedFile':str(self.directory/'host-signing.seed'),
            'originalEnvelopeFile':str(self.directory/'original-envelope.json'),
            'enrollment':{'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
                'organizationId':'org-one','stream':'IDENTITY','domain':'','streamCreated':self.identity_created,
                'minimumSequence':snapshot.sequence,'maxBytes':self.policy.max_bytes,'replicas':1,
                'hostTransportRef':ref('host-transport'),'hostIdentityRef':ref('host'),
                'issuerRef':ref('issuer'),'issuerIdentityRef':ref('service'),'issuerInstanceId':'ingress-one'},
            'service':{'profileId':'profile-one','hubId':'hub-one','serviceId':self.service_id,
                'serviceInstanceId':'storage-one','serviceIdentityRef':ref('storage-service'),
                'signingKeyRef':ref('storage-signer')},'bindingId':'storage-binding','resourceRef':ref('task-one'),
            'resourceDigest':'sha256:'+hashlib.sha256(self.original).hexdigest(),
            'requestContractId':self.read_contract,
            'replyContractId':'capability-outcome-query-reply' if self.read_contract=='capability-outcome-query' else 'capability-content-reply',
            'requestInput':self.read_input,
            'replyPayloadDigest':self.expected_reply_digest(),'revoked':False}
        self.write_private('fixture-ready.json',ready)
        result=await self.wait_handoff('go-result.json',lambda value:value.get('phase')=='read-complete')
        self.assertEqual(result,{'phase':'read-complete'})
        if self.private_child:
            await self.assert_parent_revocation_gates()
        else:
            await self.command('identity-revoke',ref('grant'),{'authorityId':'authority-one','targetRef':ref('storage-read')})
        ready['revoked']=True
        self.write_private('fixture-ready.json',ready)
        result=await self.wait_handoff('go-result.json',lambda value:value.get('phase')=='complete')
        self.assertEqual(result,{'phase':'complete','read':True,'revocation':True,'cleanup':True})
        code=await asyncio.wait_for(asyncio.shield(self.go_wait),3)
        self.assertEqual(code,0)
        if os.fstat(self.go_output.fileno()).st_size>65536:
            self.keep_directory=True
            raise RuntimeError('capability_fixture_go_output_limit')

    async def assert_parent_revocation_gates(self):
        # Reuse Go's exact still-valid request; extra preparation would consume
        # the short authorization window before Go can check revocation.
        prepared=await self.wait_handoff('go-prepared.json',lambda value:True)
        raw=base64.b64decode(prepared['request'])
        reply=strict_loads(raw)['claims']['replySubject']
        original_read=self.receiver._receiver.handle
        original_handle=self.receiver.handle
        completed=asyncio.Event()
        refused=False
        read_completed=False
        async def read_then_revoke(envelope, **kwargs):
            nonlocal read_completed
            result=await original_read(envelope, **kwargs)
            read_completed=True
            await self.command('identity-revoke',ref('grant'),{
                'authorityId':'authority-one','targetRef':ref('parent-plugin')})
            return result
        async def observe(*args,**kwargs):
            nonlocal refused
            try:
                return await original_handle(*args,**kwargs)
            except ContractError as error:
                refused=str(error)=='capability_service_unavailable'
                raise
            finally:
                completed.set()
        sub=await self.host.subscribe(reply)
        try:
            with patch.object(self.receiver._receiver,'handle',side_effect=read_then_revoke) as read, \
                    patch.object(self.receiver,'handle',side_effect=observe):
                await self.host.flush(timeout=2)
                await self.host.publish(self.read_subject,raw,reply=reply)
                await asyncio.wait_for(completed.wait(),2)
                self.assertTrue(read_completed and refused)
                self.assertEqual(read.await_count,1)
                with self.assertRaises(nats.errors.TimeoutError):await sub.next_msg(timeout=.1)
            completed.clear()
            refused=False
            with patch.object(self.receiver._receiver,'handle') as read, \
                    patch.object(self.receiver,'handle',side_effect=observe):
                await self.host.publish(self.read_subject,raw,reply=reply)
                await asyncio.wait_for(completed.wait(),2)
                read.assert_not_called()
                self.assertTrue(refused)
                with self.assertRaises(nats.errors.TimeoutError):await sub.next_msg(timeout=.1)
        finally:
            await sub.unsubscribe()

    async def assert_read_path_refusal(self):
        original_input=self.read_input
        if self.read_contract=='capability-artifact-read':bad={'digest':'sha256:'+'0'*64}
        elif self.read_contract=='capability-workspace-read':bad={'relativePath':'link'}
        elif self.read_contract=='capability-outcome-query':bad={**original_input,'payloadDigest':'sha256:'+'0'*64}
        else:return
        reply=self.host.new_inbox()
        try:
            self.read_input=bad
            raw=await self.prepare(reply)
        finally:self.read_input=original_input
        original=self.receiver.handle
        original_read=self.receiver._receiver._read
        expected_owner_error={'capability-artifact-read':'capability_service_unavailable',
            'capability-workspace-read':'capability_workspace_unavailable',
            'capability-outcome-query':'capability_outcome_conflict'}[self.read_contract]
        owner_refused=False
        async def observe_read(*args,**kwargs):
            nonlocal owner_refused
            try:return await original_read(*args,**kwargs)
            except ContractError as error:
                owner_refused=str(error)==expected_owner_error
                raise
        completed=asyncio.Event()
        refused=False
        async def observe(*args,**kwargs):
            nonlocal refused
            try:return await original(*args,**kwargs)
            except ContractError as error:
                refused=str(error)=='capability_service_unavailable'
                raise
            finally:completed.set()
        sub=await self.host.subscribe(reply)
        try:
            with patch.object(self.receiver,'handle',side_effect=observe), \
                    patch.object(self.receiver._receiver,'_read',side_effect=observe_read) as read:
                await self.host.flush(timeout=2)
                await self.host.publish(self.read_subject,raw,reply=reply)
                await asyncio.wait_for(completed.wait(),2)
                self.assertTrue(refused and owner_refused)
                self.assertEqual(read.await_count,1)
                with self.assertRaises(nats.errors.TimeoutError):await sub.next_msg(timeout=.1)
        finally:await sub.unsubscribe()

    async def assert_kernel_subject_denials(self):
        prefix='amx.v1.h.hub-one.kernel.'
        targets=[prefix+'internal.boot.command',prefix+'reply.capability-probe']
        observer=self.connections[0]
        observed=[await observer.subscribe(subject) for subject in targets]
        denied_subscriptions=[]
        leaked=[]
        async def unexpected(message):leaked.append(message.data)
        try:
            await observer.flush(timeout=2)
            for role,connection in (('host',self.host),('other-scope',self.attacker)):
                before=self.errors[role].count('permission')
                for subject in targets:
                    await connection.publish(subject,b'kernel-denial-probe')
                for subject in (*targets,prefix+'internal.>',prefix+'reply.>',prefix+'>'):
                    denied_subscriptions.append(await connection.subscribe(subject,cb=unexpected))
                await connection.flush(timeout=2)
                await self.wait_permissions(role,before+7)
                self.assertEqual(self.errors[role].count('permission'),before+7)
            # A valid observer publication proves rejected subscriptions cannot
            # receive matching traffic; denied caller publications deliver none.
            for sub in observed:
                with self.assertRaises(nats.errors.TimeoutError):await sub.next_msg(timeout=.1)
            for subject in targets:await observer.publish(subject,b'authorized-observer-probe')
            await observer.flush(timeout=2)
            for sub in observed:self.assertEqual((await sub.next_msg(timeout=1)).data,b'authorized-observer-probe')
            await self.host.flush(timeout=2)
            await self.attacker.flush(timeout=2)
            self.assertEqual(leaked,[])
        finally:
            for sub in [*denied_subscriptions,*observed]:await sub.unsubscribe()

    async def assert_live_child_widening(self):
        original=copy.deepcopy(self.row)
        def resource(row):row['facts']['grant']['resourceIds'].append('task-other')
        def project(row):
            row['facts']['grant']['scope']['projectId']='other-project'
            row['facts']['policy']['scope']['projectId']='other-project'
        def delegated_class(value):
            def change(row):row['facts']['parentAccess'].append({
                'action':'read','resourceClass':value,'resourceId':'task-one'})
            return change
        cases={'storage-resource':resource,'secret-tuple':delegated_class('secret'),
            'nats-tuple':delegated_class('nats'),'project-scope':project}
        for name,change in cases.items():
            with self.subTest(widening=name):
                widened=copy.deepcopy(original)
                previous=copy.deepcopy(self.row['ref'])
                widened['ref']['revision']=previous['revision']+1
                change(widened)
                await self.command('identity-native-instance-set',ref('native-admin'),{
                    'authorityId':'authority-one','record':widened,'previousRef':previous})
                self.row=widened
                finished=asyncio.Event()
                refused=False
                actual=self.identity.native.handle
                expected_error='native_host_not_authorized' if name=='project-scope' else 'native_parent_binding_invalid'
                async def observe(raw):
                    nonlocal refused
                    try:return await actual(raw)
                    except ContractError as error:
                        refused=str(error)==expected_error
                        raise
                    finally:finished.set()
                with patch.object(self.identity.native,'handle',side_effect=observe):
                    # Identity returns a fixed unsigned error, never native facts.
                    # The trusted verifier must reject that as an invalid response.
                    with self.assertRaisesRegex(ContractError,'^schema_invalid$'):
                        await self.native('bind-instance',{key:self.row[key] for key in
                            ('manifestDigest','relationship','parentOwner','configurationChecksum')},timeout=.25)
                    await asyncio.wait_for(finished.wait(),1)
                    self.assertTrue(refused)
                restored=copy.deepcopy(original)
                restored['ref']['revision']=widened['ref']['revision']+1
                await self.command('identity-native-instance-set',ref('native-admin'),{
                    'authorityId':'authority-one','record':restored,'previousRef':widened['ref']})
                self.row=restored
        bound=await self.native('bind-instance',{key:self.row[key] for key in
            ('manifestDigest','relationship','parentOwner','configurationChecksum')})
        self.assertEqual(bound,self.row['facts'])

    async def wait_permissions(self,role,count):
        # Broker errors arrive on the client's asynchronous callback; PONG is
        # not a completion barrier for that callback's delivery.
        async with asyncio.timeout(1):
            while self.errors[role].count('permission')<count:
                self.permission_events[role].clear()
                if self.errors[role].count('permission')<count:
                    await self.permission_events[role].wait()

    async def assert_private_inbox_permissions(self):
        victim=self.host.new_inbox()
        own=self.attacker.new_inbox()
        observed=await self.host.subscribe(victim)
        attacker_own=await self.attacker.subscribe(own)
        leaked=[]
        async def unexpected(message):
            leaked.append(message.data)
        subscriptions=[]
        try:
            # Exact, principal-wide and global subscriptions must all fail.
            for subject in (victim,self.inbox_prefixes['host']+'.>','_INBOX.>'):
                subscriptions.append(await self.attacker.subscribe(subject,cb=unexpected))
            await self.attacker.flush(timeout=2)
            await self.wait_permissions('other-scope',3)
            self.assertGreaterEqual(self.errors['other-scope'].count('permission'),3)
            self.assertEqual(leaked,[])
            # A service has only bounded reply permission granted by receipt of
            # a request. It cannot publish to an unrelated live client inbox.
            for connection,role in ((self.attacker,'other-scope'),
                                    (self.receiver._connection,'storage'),
                                    (self.identity._connection,'identity')):
                before=self.errors[role].count('permission')
                await connection.publish(victim,b'unsigned-forgery')
                await connection.flush(timeout=2)
                await self.wait_permissions(role,before+1)
                self.assertEqual(self.errors[role].count('permission'),before+1)
            with self.assertRaises(nats.errors.TimeoutError):await observed.next_msg(timeout=.25)
            with self.assertRaises(nats.errors.TimeoutError):await attacker_own.next_msg(timeout=.25)
        finally:
            for subscription in subscriptions:await subscription.unsubscribe()
            await attacker_own.unsubscribe()
            await observed.unsubscribe()

    async def test_tls_retained_read_current_authority_and_isolation(self):
        await self.assert_private_inbox_permissions()
        initial_errors={role:len(values) for role,values in self.errors.items()}
        bound=await self.native('bind-instance',{key:self.row[key] for key in
            ('manifestDigest','relationship','parentOwner','configurationChecksum')})
        self.assertEqual(bound,self.row['facts'])
        raw,response=await self.read()
        altered=strict_loads(response);altered['claims']['payload']['data']='dGFtcGVyZWQ='
        with self.assertRaisesRegex(ContractError,'^capability_reply_unconfirmed$'):
            verify_capability_response(canonical_bytes(altered),raw,public_key=self.service_public,
                signing_key_ref=ref('storage-signer'),service_identity_ref=ref('storage-service'),
                service_instance_id='storage-one',now=datetime.now(timezone.utc))
        for field,value in [('serviceId','artifact-owner'),('operationId','other-operation'),
                            ('requestId','other-request'),('owner',{**self.row['owner'],'generation':2}),
                            ('scope',{'organizationId':'other-org','projectId':None,'workspaceId':None})]:
            with self.subTest(binding=field):
                await self.read(change=lambda claims,k=field,v=value:claims.update({k:v}),expect_reply=False)
        await self.read(resource={**ref('task-one'),'revision':2},expect_reply=False)
        await self.read(received_reply=self.host.new_inbox(),expect_reply=False)
        await self.read(connection=self.attacker,expect_reply=False)
        await self.attacker.flush(timeout=2)
        self.assertIn('permission',self.errors['other-scope'])
        with self.assertRaises(Exception):await self.host.jetstream(timeout=.25).get_msg('OTHER',seq=1,direct=False)
        with self.assertRaises(Exception):await self.host.jetstream(timeout=.25).publish(self.subjects['DATA'],b'{}',timeout=.25)
        with self.assertRaises(Exception):await self.host.jetstream(timeout=.25).delete_stream('DATA')
        await self.host.flush(timeout=2)
        self.assertGreaterEqual(self.errors['host'].count('permission'),3)
        # Prepare while allowed, then revoke through the real identity command owner.
        reply=self.host.new_inbox()
        prepared=await self.prepare(reply)
        await self.run_go_read_and_revocation()
        with self.assertRaises(nats.errors.TimeoutError):
            await self.exchange(self.host,self.read_subject,prepared,reply,timeout=.25)
        self.assertEqual((await self.connections[0].jetstream().stream_info('DATA')).state.messages,1)
        self.assertEqual((await self.connections[0].jetstream().stream_info('OTHER')).state.messages,1)
        self.assertEqual(len(self.errors['identity']),initial_errors['identity'])
        self.assertEqual(len(self.errors['storage']),initial_errors['storage'])
        await self.receiver.close()
        self.assertTrue(self.receiver._cleanup_task.done())
        self.assertFalse(self.receiver._active or self.receiver._callbacks)
        self.assertEqual(self.receiver._subscription.pending_msgs,0)
        self.success=True

    async def cleanup_owned(self):
        # Join the original child and its file output before borrowed services.
        if self.go_wait is not None and not self.go_wait.done():
            self.keep_directory=True
            self.go_process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(self.go_wait),3)
            except TimeoutError:
                self.go_process.kill()
                await asyncio.wait_for(asyncio.shield(self.go_wait),3)
        if self.go_wait is not None:
            code=await self.go_wait
            if code:self.keep_directory=True
        if self.go_output is not None:self.go_output.close()
        # Retain dependencies if either service fails to join.
        if self.receiver is not None:await self.receiver.close()
        if getattr(self, 'workspace_checkout', None) is not None:
            try:
                await self.workspace_checkout.close(timeout=10)
            except BaseException:
                self.keep_directory=True
                raise
        if self.workspace is not None:self.workspace.close()
        if self.checkout_store is not None:self.checkout_store.db.close()
        if self.git_executor is not None:self.git_executor.shutdown(wait=True)
        if self.identity is not None:await asyncio.wait_for(self.identity.close(),10)
        for connection in reversed(self.connections):
            await connection.close()
        if self.broker is not None:self.broker.stop()
        if self.success and not self.keep_directory:shutil.rmtree(self.directory)


class LivePrivateCapabilityTests(LiveCapabilityTests):
    private_child=True

    async def test_tls_retained_read_current_authority_and_isolation(self):
        await self.assert_read_path_refusal()
        await self.run_go_read_and_revocation()
        self.assertEqual((await self.connections[0].jetstream().stream_info('DATA')).state.messages,1)
        await self.receiver.close()
        self.assertTrue(self.receiver._cleanup_task.done())
        self.assertFalse(self.receiver._active or self.receiver._callbacks)
        self.assertEqual(self.receiver._subscription.pending_msgs,0)
        self.success=True


class LiveArtifactCapabilityTests(LivePrivateCapabilityTests):
    read_contract='capability-artifact-read'
    read_class='artifact'


class LiveWorkspaceCapabilityTests(LivePrivateCapabilityTests):
    read_contract='capability-workspace-read'
    read_class='workspace'


class LiveOutcomeCapabilityTests(LivePrivateCapabilityTests):
    read_contract='capability-outcome-query'
    read_class='outcome'
    read_action='inspect'


class LiveCapabilityBoundaryTests(LivePrivateCapabilityTests):
    boundary_checks=True

    async def test_tls_retained_read_current_authority_and_isolation(self):
        await self.assert_kernel_subject_denials()
        await self.assert_live_child_widening()
        await super().test_tls_retained_read_current_authority_and_isolation()
