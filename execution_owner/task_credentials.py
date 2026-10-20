"""One fixed task credential owner. Public state contains references only."""
import asyncio
import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import ssl
import uuid
from urllib.parse import urlsplit

import nkeys
from nacl.signing import SigningKey, VerifyKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.nats_transport import new_client
from identity.application_account import ApplicationAccountAuthority
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot, approval_reason
from identity.ingress import EnrolledIngress
from integration_owner.operator_provisioning import _account_seed, _close_client, _encoded
from native_security.descriptor_admission import DescriptorPurpose
from native_security.nats_credentials import validate as validate_credential
from native_security.secret_custody import ScopedSecretCustody, _admit, _open_root, _open_namespace, _read_file
from state_owner.checkpoints import _publish
from state_owner.ledger import OwnerLedger, find_outcome, validate_record
from state_owner.task_service import TaskService, verify_task_reply, task_source_pin, RESPONSE_LIMIT
from .container import TaskContainerAdapter, RetainedContainerIntent
from .plans import ExecutionAdmission, _stamp
from .task_credential_program import PROOF

COMMANDS = frozenset('task-credential-'+name for name in ('prepare','deliver','observe','retire'))


def _fail(code='task_credential_refused'):
    raise ContractError(code) from None


def _reference(name, value, hub):
    return {'id': name+'-'+payload_digest(value).split(':',1)[1], 'ownerHubId':hub,'revision':1}


@dataclass(frozen=True, slots=True, repr=False)
class TaskCredentialPolicy:
    """Host-selected TLS destination for the approved fixed consumer."""
    consumer_ref: bytes
    endpoint: str
    server_name: str
    trust_pem: bytes
    leaf_certificate_sha256: str
    account_ref: bytes
    account_public_key: str
    identity_issuer_ref: bytes
    reply_prefix: str
    max_seconds: int = 30

    def __post_init__(self):
        try:
            for value in (self.consumer_ref,self.account_ref,self.identity_issuer_ref):
                validate('execution-plan-read',{'planRef':strict_loads(value)})
                if canonical_bytes(strict_loads(value))!=value:raise ValueError()
            url=urlsplit(self.endpoint)
            if (url.scheme!='tls' or not url.hostname or not url.port or url.username or url.password
                    or url.path or url.query or url.fragment
                    or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',self.server_name)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}',self.leaf_certificate_sha256)
                    or not re.fullmatch(r'A[A-Z2-7]{55}',self.account_public_key)
                    or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}',self.reply_prefix)
                    or type(self.max_seconds) is not int or not 1<=self.max_seconds<=30
                    or type(self.trust_pem) is not bytes or not 0<len(self.trust_pem)<=16384):raise ValueError()
            ssl.create_default_context(cadata=self.trust_pem.decode('ascii'))
        except Exception:_fail('task_credential_policy_invalid')

    def __repr__(self):return '<TaskCredentialPolicy selected references>'

    def pin(self):
        return {'consumerRef':strict_loads(self.consumer_ref),'endpointDigest':payload_digest(self.endpoint),
            'serverName':self.server_name,'trustDigest':'sha256:'+hashlib.sha256(self.trust_pem).hexdigest(),
            'leafPin':self.leaf_certificate_sha256,'accountRef':strict_loads(self.account_ref),
            'accountPublicKey':self.account_public_key,'identityIssuerRef':strict_loads(self.identity_issuer_ref),
            'replyPrefix':self.reply_prefix,'maxSeconds':self.max_seconds}


def _subject(record):
    scope=record['scope']
    return '.'.join(('amx','v1','h',record['runRef']['ownerHubId'],'o',scope['organizationId'],
        'p',scope['projectId'],'w',scope['workspaceId'] or '_','task-credential',record['credentialRef']['id'],'command'))


def _issue(seed, publish, subscribe, expires, *, issued=None):
    account=user=None
    try:
        account=nkeys.from_seed(seed)
        user=nkeys.from_seed(nkeys.encode_seed(secrets.token_bytes(32),nkeys.PREFIX_BYTE_USER))
        now=int(datetime.now(timezone.utc).timestamp())
        if expires<=now:_fail('task_credential_expired')
        claims={'iat':now if issued is None else issued,'exp':expires,'iss':account.public_key.decode(),'sub':user.public_key.decode(),
            'name':'agentmux-assigned-task-consumer'}
        claims['jti']=base64.b32encode(hashlib.new('sha512_256',canonical_bytes(claims)).digest()).decode().rstrip('=')
        # Finite literal subjects, one subscription, bounded aggregate bytes and frame.
        claims['nats']={'type':'user','version':2,'pub':{'allow':[publish]},'sub':{'allow':[subscribe]},
            'subs':1,'data':4*RESPONSE_LIMIT,'payload':RESPONSE_LIMIT}
        body=_encoded({'typ':'JWT','alg':'ed25519-nkey'})+b'.'+_encoded(claims)
        jwt=body+b'.'+base64.urlsafe_b64encode(account.sign(body)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n'+jwt+b'\n------END NATS USER JWT------\n\n'
            +b'-----BEGIN USER NKEY SEED-----\n'+user.seed+b'\n------END USER NKEY SEED------\n')
    finally:
        if user is not None:user.wipe()
        if account is not None:account.wipe()


class _TaskCredentialStore:
    """Immutable generation and monotonic private delivery claim, descriptor safe."""
    def __init__(self,root):
        self._path=Path(root);self._fd=_open_root(self._path)
        self._identity=self._identity_of(self._fd)

    def __repr__(self):return '<TaskCredentialStore private>'

    @staticmethod
    def _identity_of(fd):
        info=os.fstat(fd)
        return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid

    def check(self):
        if self._fd is None:_fail('task_credential_closed')
        _admit(self._fd,DescriptorPurpose.PRIVATE_DIRECTORY)
        current=_open_root(self._path)
        try:
            if self._identity_of(current)!=self._identity:_fail('task_credential_custody_changed')
        finally:os.close(current)

    @contextmanager
    def access(self,generation):
        validate('execution-plan-read',{'planRef':generation})
        self.check();directory=None
        try:
            fcntl.flock(self._fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            directory=_open_namespace(self._fd,'task-'+payload_digest(generation).split(':',1)[1],create=True)
            yield directory
            self.check()
        except BlockingIOError:_fail('task_credential_custody_busy')
        finally:
            if directory is not None:os.close(directory)
            fcntl.flock(self._fd,fcntl.LOCK_UN)

    @staticmethod
    def read(directory,name):
        try:return _read_file(directory,name)
        except FileNotFoundError:return None

    @staticmethod
    def match(directory,name,raw):
        prior=_TaskCredentialStore.read(directory,name)
        if prior is None:
            try:_publish(directory,name,raw,admit=lambda fd:_admit(fd,DescriptorPurpose.PRIVATE_FILE))
            except FileExistsError:pass
            prior=_TaskCredentialStore.read(directory,name)
        if prior!=raw:_fail('task_credential_custody_conflict')

    def close(self):
        if self._fd is not None:os.close(self._fd);self._fd=None


class TaskCredentialOwner:
    """Owns one exact approved run's finite credential and fixed read consumer.

    No caller supplies a signing callback, program, endpoint, raw material or
    alternate resolver. Account keys remain in the existing account custody.
    """
    def __init__(self,authority,ledger,account_custody,adapter,task_service,*,policy,
                 custody_root,owner_identity_ref):
        if (type(authority) is not LedgerAuthorityReader or not isinstance(ledger,OwnerLedger)
                or type(account_custody) is not ScopedSecretCustody or account_custody._authority is not authority
                or type(adapter) is not TaskContainerAdapter or adapter._plans._authority is not authority
                or type(task_service) is not TaskService or task_service.owner is not adapter._plans._task
                or task_service.ingress._reader is not authority
                or task_service.ingress._session_authorizer is not None
                or type(policy) is not TaskCredentialPolicy
                or (ledger._binding.owner_domain,ledger._binding.entity_kind)!=('task-credentials','effect')
                or ledger._binding.scope!=adapter._plans._ledger._binding.scope
                or ledger._binding.hub_id!=authority._hub or not ledger.completion_budget_required):
            _fail('task_credential_configuration')
        validate('execution-plan-read',{'planRef':owner_identity_ref})
        profile=strict_loads(adapter._plans._profile)
        if (policy.consumer_ref!=canonical_bytes(profile['consumerRef'])
                or owner_identity_ref in (profile['workerIdentityRef'],profile['consumerRef'])
                or owner_identity_ref['ownerHubId']!=authority._hub
                or ledger._binding.entity_id!=profile['credentialRef']['id']
                or profile['credentialRef']['revision']!=1
                or task_service._identity!=policy.consumer_ref
                or task_service._reply_prefix!=policy.reply_prefix+'.'
                or task_service.ingress._issuer_ref!=policy.identity_issuer_ref
                or task_service.source_pin!=task_source_pin(task_service.owner._ledger,
                    account_public_key=policy.account_public_key,jetstream_domain=None)):
            _fail('task_credential_configuration')
        self._authority,self._ledger,self._account_custody=authority,ledger,account_custody
        self._adapter,self._task_service,self._policy=adapter,task_service,policy
        self._account=ApplicationAccountAuthority(authority)
        self._owner=canonical_bytes(owner_identity_ref);self._profile=profile
        self._store=_TaskCredentialStore(custody_root)
        self._gate=asyncio.Lock();self._jobs=set();self._clients=[];self._closed=False
        self._handlers=set();self._proofs=set();self._subscriptions=[];self._closing=None
        self._delivery_ack=None

    def __repr__(self):return '<TaskCredentialOwner private>'

    async def _owned(self,method,*args):
        if self._closed or len(self._jobs)>=8:_fail('task_credential_unavailable')
        async def run():
            try:
                async with self._gate:return await method(*args)
            except asyncio.CancelledError:raise
            except ContractError:raise
            except Exception:_fail()
        task=asyncio.create_task(run(),name='task-credential-owner');self._jobs.add(task)
        def done(original):
            self._jobs.discard(original)
            if not original.cancelled():original.exception()
        task.add_done_callback(done)
        await asyncio.wait((task,))
        return task.result()

    async def _authorize(self,raw,contract):
        if self._closed:_fail('task_credential_closed')
        env=strict_loads(raw);validate('message-envelope',env)
        if env['contractId']!=contract or canonical_bytes(env)!=raw:_fail()
        validate(contract,env['payload'])
        op=env['operation'];ref=env['payload']['credentialRef']
        if (canonical_bytes(op['effectiveActorRef'])!=self._owner or op['caller']['kind']!='service'
                or canonical_bytes(op['scope'])!=self._ledger._binding.scope
                or ref!=self._profile['credentialRef']):_fail('task_credential_owner_required')
        snapshot=await self._authority.current();now=datetime.now(timezone.utc)
        decision=evaluate_snapshot(snapshot,raw,audience={'hubId':self._authority._hub,'serviceId':'process-owner'},now=now)
        if (decision.outcome!='allowed' or decision.valid_until is None or now>=decision.valid_until
                or decision.operation!=canonical_bytes(op)):_fail('task_credential_not_authorized')
        return env,decision.valid_until

    async def _account_current(self,request,record=None):
        value=await self._account.resolve(request)
        if (canonical_bytes(value.account_ref)!=self._policy.account_ref
                or value.account_public_key!=self._policy.account_public_key
                or value.scope!={**self._profile['scope'],'workspaceId':None}
                or value.profile_id!=self._authority._profile
                or record is not None and value.account_issuer_ref!=record['accountIssuerRef']):_fail()
        return value

    async def _admission(self,admission,inspection,run_ref):
        if type(admission) is not ExecutionAdmission or admission._owner is not self._adapter._plans:_fail()
        admission=await admission.recheck(inspection);binding=strict_loads(admission.binding)
        if binding['runRef']!=run_ref:_fail('task_credential_original_mismatch')
        return admission,binding

    def _history(self,snapshot):
        prior=None
        transitions={None:{'prepared'},'prepared':{'delivery-intent','retired'},
            'delivery-intent':{'delivered','uncertain','retired'},'delivered':{'retired'},
            'uncertain':{'retired'},'retired':set()}
        for stored in snapshot.records:
            item=validate_record(stored.record,self._ledger._binding);state=item['state']
            validate('task-credential-state',state);validate('task-credential-record',state['record'])
            r=state['record'];op=item['operation'];contract=item['authorizationDecision'].get('contractId')
            expected={'prepared':'task-credential-prepare','delivery-intent':'task-credential-deliver',
                'delivered':'task-credential-observe','uncertain':'task-credential-observe','retired':'task-credential-retire'}
            if (state['phase'] not in transitions[None if prior is None else prior['phase']]
                    or prior is not None and r!=prior['record']
                    or r['credentialRef']!=self._profile['credentialRef']
                    or r['ownerIdentityRef']!=strict_loads(self._owner)
                    or r['policyDigest']!=payload_digest(self._policy.pin())
                    or op['effectiveActorRef']!=r['ownerIdentityRef']
                    or contract!=expected[state['phase']] or item['outcome']!='committed'
                    or op['expectedVersion']!=stored.sequence-1
                    or item['authorizationDecision']!={'operationId':op['operationId'],'decision':'allowed',
                        'reason':'authorized','actorRef':op['effectiveActorRef'],'contractId':contract}
                    or r['expiresUnix']<=r['issuedUnix']
                    or r['expiresUnix']-r['issuedUnix']>self._policy.max_seconds
                    or r['profileId']!=self._authority._profile or r['authorityId']!=self._authority._entity
                    or canonical_bytes(r['scope'])!=self._ledger._binding.scope
                    or item['effects'] or item['artifacts']
                    or r['destinationRef']!=r['consumerRef']):_fail('task_credential_history_invalid')
            if state['phase']=='prepared':
                payload={'credentialRef':r['credentialRef'],'runRef':r['runRef'],
                    'taskReadGrantRef':r['taskReadGrantRef'],'taskApprovalRefs':r['taskApprovalRefs']}
                if state['resourceRef'] is not None or state['deliveryOperationId'] is not None:_fail()
            else:
                payload={'credentialRef':r['credentialRef'],'runRef':r['runRef']}
                if state['phase']=='delivery-intent':
                    if state['resourceRef'] is None or state['deliveryOperationId']!=op['operationId']:_fail()
                elif state['resourceRef']!=prior['resourceRef'] or state['deliveryOperationId']!=prior['deliveryOperationId']:_fail()
            if op['payloadDigest']!=payload_digest(payload):_fail('task_credential_history_invalid')
            prior=state
        return prior

    async def _append(self,env,state,snapshot,end):
        b=self._ledger._binding;op=env['operation']
        record={'schemaVersion':'1.0.0','recordId':'task-credential-'+uuid.uuid4().hex,
            'entityId':b.entity_id,'entityKind':b.entity_kind,'ownerHubId':b.hub_id,'ownerDomain':b.owner_domain,
            'entityVersion':snapshot.sequence+1,'previousRevision':snapshot.sequence,'operation':op,
            'recordedAt':_stamp(datetime.now(timezone.utc)),'outcome':'committed','state':state,
            'effects':[],'artifacts':[],'repository':None,'authorizationDecision':{
                'operationId':op['operationId'],'decision':'allowed','reason':'authorized',
                'actorRef':op['effectiveActorRef'],'contractId':env['contractId']}}
        # Intent reserves observation and retirement even when the original expires.
        budget={'prepared':3,'delivery-intent':2,'delivered':1,'uncertain':1,'retired':0}[state['phase']]
        await self._ledger.append(record,expected_sequence=snapshot.sequence,valid_until=end,completion_records=budget)
        return state

    def _decode(self,raw,record=None):
        value=strict_loads(raw)
        if (canonical_bytes(value)!=raw or set(value)!={'format','record','credentialsBase64'}
                or value['format']!='agentmux-task-credential-private-v1'
                or len(raw)>16384):_fail('task_credential_custody_changed')
        r=value['record'];validate('task-credential-record',r)
        if record is not None and r!=record:_fail('task_credential_custody_changed')
        material=base64.b64decode(value['credentialsBase64'],validate=True)
        credential=validate_credential(material,account_public_key=r['accountPublicKey'],
            publish_subjects=(_subject(r),),subscribe_subjects=(r['replySubject'],))
        claims=strict_loads(base64.urlsafe_b64decode(credential.jwt.split('.')[1]+'==='))
        if (credential.public_key!=r['userPublicKey'] or claims['exp']!=r['expiresUnix']
                or claims['iat']!=r['issuedUnix'] or r['expiresUnix']-r['issuedUnix']>self._policy.max_seconds
                or claims['nats']['subs']!=1 or claims['nats']['data']!=4*RESPONSE_LIMIT
                or claims['nats']['payload']!=RESPONSE_LIMIT):_fail('task_credential_custody_changed')
        return r,credential

    async def prepare(self,raw,admission,*,task_inspection,account_request):
        """Return only public generation metadata and an enrollment possession proof."""
        return await self._owned(self._prepare,raw,admission,task_inspection,account_request)

    async def _prepare(self,raw,admission,inspection,account_request):
        env,end=await self._authorize(raw,'task-credential-prepare');payload=env['payload']
        admission,binding=await self._admission(admission,inspection,payload['runRef'])
        account=await self._account_current(account_request)
        snapshot=await self._ledger.current();state=self._history(snapshot)
        original={'binding':binding,'prepareOperationId':env['operation']['operationId']}
        generation=_reference('task-generation',original,self._authority._hub)
        assignment={'generationRef':generation,'bindingDigest':payload_digest(binding),
            'prepareOperationId':env['operation']['operationId'],'policyDigest':payload_digest(self._policy.pin()),
            'taskReadGrantRef':payload['taskReadGrantRef'],'taskApprovalRefs':payload['taskApprovalRefs']}
        with self._store.access(generation) as directory:
            self._store.match(directory,'assignment.json',canonical_bytes(assignment))
            private=self._store.read(directory,'credential.json')
        if state is not None:
            if (state['phase']=='retired' or any(state['record'][k]!=v for k,v in assignment.items())):_fail('task_credential_original_mismatch')
            if private is None:_fail('task_credential_recovery_required')
        elif snapshot.sequence!=env['operation']['expectedVersion']:_fail('owner_revision_conflict')
        if private is None:
            issued=int(datetime.now(timezone.utc).timestamp())
            expires=int(min(admission.valid_until,account.valid_until,end,
                datetime.now(timezone.utc)+timedelta(seconds=self._policy.max_seconds)).timestamp())
            record={'schemaVersion':'1.0.0',**assignment,**{k:binding[k] for k in
                ('credentialRef','runRef','planRef','taskRef','workerIdentityRef','consumerRef','scope','attemptId')},
                'workspaceRef':self._profile['workspaceRef'],'networkProfileRef':self._profile['network']['profileRef'],
                'destinationRef':binding['consumerRef'],'accountRef':account.account_ref,
                'accountIssuerRef':account.account_issuer_ref,'accountPublicKey':account.account_public_key,
                'ownerIdentityRef':strict_loads(self._owner),'profileId':self._authority._profile,
                'authorityId':self._authority._entity,'identityIssuerRef':strict_loads(self._policy.identity_issuer_ref),
                'transportRef':_reference('task-transport',original,self._authority._hub),
                'readOperationId':'task-read-'+payload_digest(original).split(':',1)[1],
                'replySubject':self._policy.reply_prefix+'.'+payload_digest(original).split(':',1)[1],
                'issuedUnix':issued,'expiresUnix':expires}
            await self._current_generation(record,admission,inspection,account_request,enrolled=False)
            authority=await self._authority.current()
            current_index=_indexes(strict_loads(authority.record)['state'],self._authority._hub)
            record['expiresUnix']=min(record['expiresUnix'],*(int(datetime.fromisoformat(item['expiresAt']).timestamp())
                for item in (current_index['grants'][_key(record['taskReadGrantRef'])],
                             current_index['issuers'][_key(record['identityIssuerRef'])])))
            expires=record['expiresUnix']
            private_issuer=await self._account_custody.resolve(account_request,kind='nats-account-issuer')
            seed=_account_seed(private_issuer,account.account_public_key)
            material=_issue(seed,_subject(record),record['replySubject'],expires,issued=record['issuedUnix'])
            del seed,private_issuer
            credential=validate_credential(material,account_public_key=account.account_public_key,
                publish_subjects=(_subject(record),),subscribe_subjects=(record['replySubject'],))
            record['userPublicKey']=credential.public_key;validate('task-credential-record',record)
            private=canonical_bytes({'format':'agentmux-task-credential-private-v1','record':record,
                'credentialsBase64':base64.b64encode(material).decode()})
            await self._account_current(account_request,record)
            await self._admission(admission,inspection,payload['runRef'])
            await self._authorize(raw,'task-credential-prepare')
            with self._store.access(generation) as directory:self._store.match(directory,'credential.json',private)
        record,credential=self._decode(private)
        if any(record[k]!=v for k,v in assignment.items()):_fail('task_credential_original_mismatch')
        await self._admission(admission,inspection,payload['runRef']);await self._account_current(account_request,record)
        _,latest=await self._authorize(raw,'task-credential-prepare')
        if state is None:
            state={'format':'agentmux-task-credential-state-v1','record':record,'phase':'prepared',
                'resourceRef':None,'deliveryOperationId':None}
            await self._append(env,state,snapshot,min(end,latest,admission.valid_until))
        elif record!=state['record']:_fail('task_credential_original_mismatch')
        enrollment=await self._enrollment(record,credential)
        await self._admission(admission,inspection,payload['runRef'])
        await self._account_current(account_request,record)
        await self._current_generation(record,admission,inspection,account_request,enrolled=False)
        await self._authorize(raw,'task-credential-prepare')
        return canonical_bytes({'record':record,'enrollment':enrollment})

    async def _enrollment(self,record,credential):
        snapshot=await self._authority.current();index=_indexes(strict_loads(snapshot.record)['state'],self._authority._hub)
        now=datetime.now(timezone.utc);issuer=index['issuers'].get(_key(record['identityIssuerRef']))
        worker=index['identities'].get(_key(record['workerIdentityRef']))
        if issuer is None or worker is None or not _active(issuer,now) or not _active(worker,now) or worker['kind']!='service':_fail()
        encoded=base64.b32decode(record['userPublicKey']+'='*(-len(record['userPublicKey'])%8))
        public=base64.urlsafe_b64encode(encoded[1:33]).decode().rstrip('=')
        transport={'ref':record['transportRef'],'identityRef':record['workerIdentityRef'],
            'issuerRef':record['identityIssuerRef'],'method':'nats-credential-mapping','publicKey':public,
            'status':'active','issuedAt':_stamp(datetime.fromtimestamp(record['issuedUnix'],timezone.utc)),
            'expiresAt':_stamp(datetime.fromtimestamp(record['expiresUnix'],timezone.utc))}
        claims={'purpose':'agentmux-enrollment-possession-v1','profileId':record['profileId'],
            'authorityId':record['authorityId'],'credential':transport}
        key=nkeys.from_seed(credential.seed)
        try:proof=base64.urlsafe_b64encode(key.sign(canonical_bytes(claims))).decode().rstrip('=')
        finally:key.wipe()
        payload={'authorityId':record['authorityId'],'identity':worker,'issuers':[],
            'transports':[{'record':transport,'proof':proof}]}
        validate('identity-enroll',payload)
        return payload

    async def _current_generation(self,record,admission,inspection,account_request,*,enrolled=True):
        if datetime.now(timezone.utc).timestamp()>=record['expiresUnix']:_fail('task_credential_expired')
        admission,binding=await self._admission(admission,inspection,record['runRef'])
        if (payload_digest(binding)!=record['bindingDigest'] or record['consumerRef']!=self._profile['consumerRef']
                or record['workerIdentityRef']!=self._profile['workerIdentityRef']
                or record['workspaceRef']!=self._profile['workspaceRef']
                or record['networkProfileRef']!=self._profile['network']['profileRef']):_fail('task_credential_original_mismatch')
        await self._account_current(account_request,record)
        snapshot=await self._authority.current();now=datetime.now(timezone.utc)
        index=_indexes(strict_loads(snapshot.record)['state'],self._authority._hub)
        service_issuer=index['issuers'].get(_key(strict_loads(self._task_service._issuer)))
        service_public=base64.urlsafe_b64encode(bytes(SigningKey(self._task_service._seed).verify_key)).decode().rstrip('=')
        if (service_issuer is None or not _active(service_issuer,now)
                or service_issuer['identityRef']!=record['consumerRef']
                or service_issuer['publicKey']!=service_public
                or service_issuer['instanceId']!=self._task_service._instance):_fail('task_credential_consumer_unavailable')
        grant=index['grants'].get(_key(record['taskReadGrantRef']))
        matches=[g for g in index['grants'].values() if _active(g,now)
            and g['callerRef']==record['workerIdentityRef'] and g['actorRef']==record['workerIdentityRef']
            and g['scope']==record['scope'] and g['contractId']=='task-inspect' and g['resourceId']==record['taskRef']['id']]
        if (grant is None or grant not in matches or grant['decision'] not in ('allowed','review-required')
                or grant['delegationRef'] is not None or any(g['decision']=='denied' for g in matches)):_fail('task_credential_worker_grant_unavailable')
        operation={'operationId':record['readOperationId'],'payloadDigest':payload_digest({'taskId':record['taskRef']['id']}),
            'expectedVersion':record['taskRef']['revision'],'approvalRefs':record['taskApprovalRefs']}
        if approval_reason(index,grant,operation,audience={'hubId':self._authority._hub,'serviceId':'task-owner'},
                scope=record['scope'],contract='task-inspect',now=now) is not None:_fail('task_credential_worker_approval_unavailable')
        issuer=index['issuers'].get(_key(record['identityIssuerRef']))
        issuer_identity=None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or issuer_identity is None or not _active(issuer,now)
                or not _active(issuer_identity,now) or issuer_identity['kind']!='service'):_fail('task_credential_enrollment_unavailable')
        if enrolled:
            transport=index['transports'].get(_key(record['transportRef']))
            issuer=index['issuers'].get(_key(record['identityIssuerRef']))
            encoded=base64.b32decode(record['userPublicKey']+'='*(-len(record['userPublicKey'])%8))
            public=base64.urlsafe_b64encode(encoded[1:33]).decode().rstrip('=')
            if (transport is None or issuer is None or not _active(transport,now) or not _active(issuer,now)
                    or transport['identityRef']!=record['workerIdentityRef']
                    or transport['issuerRef']!=record['identityIssuerRef'] or transport['publicKey']!=public
                    or transport['method']!='nats-credential-mapping'
                    or datetime.fromisoformat(transport['expiresAt']).timestamp()>record['expiresUnix']):_fail('task_credential_enrollment_unavailable')
        return admission

    def _private(self,record):
        with self._store.access(record['generationRef']) as directory:
            raw=self._store.read(directory,'credential.json')
        if raw is None:_fail('task_credential_recovery_required')
        self._decode(raw,record)
        return raw

    async def deliver(self,raw,admission,*,task_inspection,account_request,intent):
        return await self._owned(self._deliver,raw,admission,task_inspection,account_request,intent)

    async def _deliver(self,raw,admission,inspection,account_request,intent):
        env,end=await self._authorize(raw,'task-credential-deliver')
        snapshot=await self._ledger.current();state=self._history(snapshot)
        if state is None or state['record']['runRef']!=env['payload']['runRef']:_fail('task_credential_original_mismatch')
        r=state['record']
        if state['phase']!='prepared':_fail('task_credential_delivery_already_attempted')
        # Reject stale intent commands before reserving an immutable claim. The
        # retained claim must name the prepared version that admitted it.
        if env['operation']['expectedVersion']!=snapshot.sequence:_fail('owner_revision_conflict')
        if env['operation']['operationId']==r['prepareOperationId']:_fail('owner_operation_conflict')
        if type(intent) is not RetainedContainerIntent or intent.binding!=admission.binding:_fail()
        admission=await self._current_generation(r,admission,inspection,account_request)
        observation=await self._adapter.observe(r['runRef'])
        if observation.status!='prepared' or observation.resource_ref is None:_fail('task_credential_container_not_prepared')
        resource=strict_loads(observation.resource_ref);validate('task-credential-container-resource',resource)
        if resource['runRef']!=r['runRef'] or resource['bindingDigest']!=r['bindingDigest']:_fail()
        material=self._private(r)
        claim=canonical_bytes({'generationRef':r['generationRef'],'runRef':r['runRef'],
            'resourceRef':resource,'operation':env['operation']})
        # A prior private claim cannot be replayed, even if a ledger append was
        # uncertain or a source was restored. Only observation/retirement follows.
        with self._store.access(r['generationRef']) as directory:
            if self._store.read(directory,'delivery.json') is not None:_fail('task_credential_delivery_uncertain')
            self._store.match(directory,'delivery.json',claim)
        state={**state,'phase':'delivery-intent','resourceRef':resource,'deliveryOperationId':env['operation']['operationId']}
        _,latest=await self._authorize(raw,'task-credential-deliver')
        await self._append(env,state,snapshot,min(end,latest,admission.valid_until))
        admission=await self._current_generation(r,admission,inspection,account_request)
        await self._authorize(raw,'task-credential-deliver')
        result=await self._adapter.deliver_private(r['runRef'],admission,task_inspection=inspection,
            intent=intent,worker_ref=r['workerIdentityRef'],consumer_ref=r['consumerRef'],material=material)
        if result.resource_ref!=observation.resource_ref or result.status!='prepared':_fail('task_credential_delivery_uncertain')
        with self._store.access(r['generationRef']) as directory:
            self._store.match(directory,'acknowledged.json',claim)
        self._delivery_ack=claim
        # Acknowledgement alone does not authorize a public result. Observe uses
        # its own current service permission and never discloses material.
        return canonical_bytes({'generationRef':r['generationRef'],'runRef':r['runRef'],'status':'delivery-observed'})

    async def observe(self,raw):return await self._owned(self._observe,raw)

    async def _observe(self,raw):
        env,end=await self._authorize(raw,'task-credential-observe')
        snapshot=await self._ledger.current();state=self._history(snapshot)
        if state is None or state['record']['runRef']!=env['payload']['runRef']:_fail()
        if state['phase']=='delivery-intent':
            r=state['record']
            with self._store.access(r['generationRef']) as directory:
                claim=self._store.read(directory,'delivery.json');ack=self._store.read(directory,'acknowledged.json')
            if claim is None:_fail('task_credential_recovery_required')
            saved=strict_loads(claim)
            if (saved['runRef']!=r['runRef'] or saved['generationRef']!=r['generationRef']
                    or saved['resourceRef']!=state['resourceRef']
                    or saved['operation']['operationId']!=state['deliveryOperationId']):_fail()
            next_phase='delivered' if ack==claim else 'uncertain'
            _,latest=await self._authorize(raw,'task-credential-observe')
            state=await self._append(env,{**state,'phase':next_phase},snapshot,min(end,latest))
        elif state['phase'] not in ('delivered','uncertain','retired'):_fail('task_credential_not_delivered')
        await self._authorize(raw,'task-credential-observe')
        return canonical_bytes(state)

    def _retirement_claim(self,record,version):
        with self._store.access(record['generationRef']) as directory:
            raw=self._store.read(directory,'delivery.json')
        if raw is None:return None
        try:
            claim=strict_loads(raw)
            if (canonical_bytes(claim)!=raw
                    or set(claim)!={'generationRef','runRef','resourceRef','operation'}):raise ValueError()
            validate('task-credential-container-resource',claim['resourceRef'])
            validate('operation-context',claim['operation'])
            operation=claim['operation'];resource=claim['resourceRef']
            if (claim['generationRef']!=record['generationRef'] or claim['runRef']!=record['runRef']
                    or resource['runRef']!=record['runRef'] or resource['bindingDigest']!=record['bindingDigest']
                    or operation['expectedVersion']!=version
                    or operation['operationId']==record['prepareOperationId']
                    or operation['effectiveActorRef']!=record['ownerIdentityRef']
                    or operation['caller']['authenticatedIdentityRef']!=record['ownerIdentityRef']
                    or operation['caller']['kind']!='service' or operation['scope']!=record['scope']
                    or operation['grantRef']['ownerHubId']!=record['runRef']['ownerHubId']
                    or operation['payloadDigest']!=payload_digest({'credentialRef':record['credentialRef'],
                        'runRef':record['runRef']})):raise ValueError()
            return claim
        except Exception:_fail('task_credential_claim_mismatch')

    async def retire(self,raw):return await self._owned(self._retire,raw)

    async def _retire(self,raw):
        env,end=await self._authorize(raw,'task-credential-retire')
        snapshot=await self._ledger.current();state=self._history(snapshot)
        if state is None or state['record']['runRef']!=env['payload']['runRef']:_fail()
        if state['phase']=='retired':
            await self._authorize(raw,'task-credential-retire')
            return canonical_bytes(state)
        if self._clients or self._subscriptions or self._handlers or self._proofs:_fail('task_credential_users_not_joined')
        r=state['record']
        resource=state['resourceRef']
        if resource is None:
            # A failed intent append leaves the private original authoritative
            # for cleanup only. It never permits another delivery or task use.
            claim=self._retirement_claim(r,snapshot.sequence)
            if claim is not None:resource=claim['resourceRef']
        if resource is not None:
            result=await self._adapter.observe(r['runRef'])
            if result.status!='terminal' or result.resource_ref!=canonical_bytes(resource):
                _fail('task_credential_physical_state_unresolved')
        # Keep immutable private history for recovery/retention. Retirement stops
        # this owner using the generation; it does not claim broker revocation or
        # release a task reservation. Rotation requires a new approved plan/run.
        _,latest=await self._authorize(raw,'task-credential-retire')
        state=await self._append(env,{**state,'phase':'retired'},snapshot,min(end,latest))
        await self._authorize(raw,'task-credential-retire')
        return canonical_bytes(state)

    async def _proof(self,record,request,admission,inspection,account_request,intent,resource):
        adapter=self._adapter
        async def sign():
            async with adapter._gate:
                run=adapter._run(record['runRef'])
                if run['unknown'] or run.get('removed') or not run.get('private_attempted'):_fail()
                await adapter._fresh(admission,inspection,intent)
                await adapter._engine.check_transport()
                adapter._verify(await adapter._engine.inspect(run['id']),run)
                if adapter._observation(run,'prepared').resource_ref!=resource:_fail()
                await self._current_generation(record,admission,inspection,account_request)
                await adapter._fresh(admission,inspection,intent)
                output=await adapter._engine.exec_fixed(run['id'],run['spec']['uid'],PROOF,data=canonical_bytes(request))
                # The program returns a signature only, with a fixed 88-byte bound.
                if type(output) is not bytes or len(output)!=88:_fail('task_credential_proof_invalid')
                signature=base64.b64decode(output,validate=True)
                if len(signature)!=64:_fail('task_credential_proof_invalid')
                message=request.get('nonce')
                message=message.encode('ascii') if request['purpose']=='broker-nonce' else canonical_bytes(request['claims'])
                encoded=base64.b32decode(record['userPublicKey']+'='*(-len(record['userPublicKey'])%8))
                VerifyKey(encoded[1:33]).verify(message,signature)
                await self._current_generation(record,admission,inspection,account_request)
                return output
        original=asyncio.create_task(adapter._owned(sign),name='task-credential-container-proof')
        self._proofs.add(original)
        def finished(done):
            self._proofs.discard(done)
            if not done.cancelled():done.exception()
        original.add_done_callback(finished)
        await asyncio.wait((original,))
        return original.result()

    async def _connect(self,record,credential,*,server,proof=None):
        client=new_client(require_tls=True,leaf_certificate_sha256=self._policy.leaf_certificate_sha256)
        self._clients.append(client);errors=[]
        async def error(_error):errors.append(True)
        signed_nonce=None
        original_info=client._process_info
        async def process_info(info,initial_connection=False):
            nonlocal signed_nonce
            await original_info(info,initial_connection=initial_connection)
            if not server and initial_connection:
                nonce=info.get('nonce')
                if type(nonce) is not str or signed_nonce is not None:_fail('task_credential_connection_refused')
                signed_nonce=(nonce,await proof(nonce))
        # The prepared NATS client requires a synchronous signature callback.
        # Await the fixed container proof after authenticated TLS INFO, before
        # that client's CONNECT. Reconnect is disabled; another nonce refuses.
        client._process_info=process_info
        def signature(nonce):
            if server:
                key=nkeys.from_seed(credential.seed)
                try:return base64.b64encode(key.sign(nonce.encode('ascii')))
                finally:key.wipe()
            if signed_nonce is None or signed_nonce[0]!=nonce:_fail('task_credential_connection_refused')
            return signed_nonce[1]
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=self._policy.trust_pem.decode('ascii'))
        async with asyncio.timeout(5):
            await client.connect(servers=[self._policy.endpoint],tls=context,tls_hostname=self._policy.server_name,
                tls_handshake_first=True,user_jwt_cb=lambda:credential.jwt.encode('ascii'),signature_cb=signature,
                inbox_prefix=self._policy.reply_prefix,allow_reconnect=False,max_reconnect_attempts=0,
                connect_timeout=3,dont_randomize=True,no_echo=True,error_cb=error)
        if client.is_connected is not True or errors:_fail('task_credential_connection_refused')
        return client,errors

    async def inspect_task(self,raw,admission,*,task_inspection,account_request,intent):
        """One fixed assigned-task read, returning references after current checks."""
        return await self._owned(self._inspect_task,raw,admission,task_inspection,account_request,intent)

    async def _inspect_task(self,raw,admission,inspection,account_request,intent):
        # Reuse the retained delivery command only as fresh owner authority; this
        # read neither re-delivers material nor appends a second effect intent.
        env,_=await self._authorize(raw,'task-credential-deliver')
        snapshot=await self._ledger.current();state=self._history(snapshot)
        if state is None or state['phase']!='delivered' or state['record']['runRef']!=env['payload']['runRef']:_fail()
        r=state['record'];resource=canonical_bytes(state['resourceRef'])
        admission=await self._current_generation(r,admission,inspection,account_request)
        if type(intent) is not RetainedContainerIntent or intent.binding!=admission.binding:_fail()
        private=self._private(r);_,credential=self._decode(private,r)
        # Only the user JWT goes to the paired host NATS client. Its signing
        # callback always invokes the exact container. The host never signs the
        # worker's live broker/task challenges with its stored user seed.
        private_issuer=await self._account_custody.resolve(account_request,kind='nats-account-issuer')
        seed=_account_seed(private_issuer,r['accountPublicKey'])
        service_material=_issue(seed,r['replySubject'],_subject(r),r['expiresUnix'])
        del private_issuer,seed
        service_credential=validate_credential(service_material,account_public_key=r['accountPublicKey'],
            publish_subjects=(r['replySubject'],),subscribe_subjects=(_subject(r),))
        client=server=subscription=reply_subscription=None
        async def fresh():
            await self._authorize(raw,'task-credential-deliver')
            await self._current_generation(r,admission,inspection,account_request)
            current=self._history(await self._ledger.current())
            if current!=state:_fail('task_credential_generation_changed')
        async def receive(message):
            async def handle():
                try:
                    await fresh()
                    if message.reply!=r['replySubject'] or message.subject!=_subject(r):return
                    value=strict_loads(message.data)
                    if value!=request:return
                    response=await self._task_service.handle(message.data,received_reply_subject=message.reply)
                    await fresh()
                    await server.publish(r['replySubject'],response)
                    await server.flush(timeout=2)
                except (Exception,asyncio.CancelledError):return
            job=asyncio.create_task(handle(),name='task-credential-fixed-consumer');self._handlers.add(job)
            def finished(original):
                self._handlers.discard(original)
                if not original.cancelled():original.exception()
            job.add_done_callback(finished)
        async def proof(nonce):
            await fresh()
            return await self._proof(r,{'purpose':'broker-nonce','generationRef':r['generationRef'],
                'runRef':r['runRef'],'nonce':nonce},admission,inspection,account_request,intent,resource)
        try:
            await fresh()
            server,server_errors=await self._connect(r,service_credential,server=True)
            subscription=await server.subscribe(_subject(r),cb=receive,pending_msgs_limit=1,pending_bytes_limit=65536)
            self._subscriptions.append(subscription)
            await server.flush(timeout=2)
            client,client_errors=await self._connect(r,credential,server=False,proof=proof)
            now=datetime.now(timezone.utc);end=min(admission.valid_until,datetime.fromtimestamp(r['expiresUnix'],timezone.utc),now+timedelta(seconds=5))
            claims={'purpose':'agentmux-client-possession-v1','profileId':r['profileId'],
                'hubId':r['runRef']['ownerHubId'],'authorityId':r['authorityId'],'transportRef':r['transportRef'],
                'grantRef':r['taskReadGrantRef'],'operationId':r['readOperationId'],
                'expectedVersion':r['taskRef']['revision'],'contractId':'task-inspect','payload':{'taskId':r['taskRef']['id']},
                'approvalRefs':r['taskApprovalRefs'],'issuedAt':_stamp(now),'expiresAt':_stamp(end),'replySubject':r['replySubject']}
            signed=await self._proof(r,{'purpose':'task-inspect','generationRef':r['generationRef'],
                'runRef':r['runRef'],'claims':claims},admission,inspection,account_request,intent,resource)
            request={'schemaVersion':'1.0.0',
                'claims':claims,'signature':base64.urlsafe_b64encode(base64.b64decode(signed,validate=True)).decode().rstrip('=')}
            validate('identity-ingress-request',request)
            reply_subscription=await client.subscribe(r['replySubject'],pending_msgs_limit=1,pending_bytes_limit=RESPONSE_LIMIT)
            self._subscriptions.append(reply_subscription)
            await client.flush(timeout=2);await fresh()
            await client.publish(_subject(r),canonical_bytes(request),reply=r['replySubject']);await client.flush(timeout=2)
            response=await reply_subscription.next_msg(timeout=max(.001,(end-datetime.now(timezone.utc)).total_seconds()))
            await fresh()
            if server_errors or client_errors:_fail('task_credential_connection_refused')
            signer=self._task_service
            snapshot=await self._authority.current();index=_indexes(strict_loads(snapshot.record)['state'],self._authority._hub)
            issuer=index['issuers'].get(_key(strict_loads(signer._issuer)))
            if issuer is None or not _active(issuer,datetime.now(timezone.utc)):_fail()
            stored=verify_task_reply(response.data,canonical_bytes(request),binding=signer.owner._ledger._binding,
                source_pin=signer.source_pin,public_key=issuer['publicKey'],
                signing_key_ref=strict_loads(signer._issuer),service_identity_ref=r['consumerRef'],
                service_instance_id=signer._instance,minimum_source_revision=r['taskRef']['revision'],now=datetime.now(timezone.utc))
            if stored.sequence!=r['taskRef']['revision']:_fail('task_credential_task_changed')
            await fresh()
            return canonical_bytes({'generationRef':r['generationRef'],'runRef':r['runRef'],
                'taskRef':r['taskRef'],'consumerRef':r['consumerRef'],'status':'inspected'})
        finally:
            await self._cleanup_users()

    async def _cleanup_users(self):
        # Keep original handles on the owner until each join succeeds. An
        # unsubscribe error on a disconnected client cannot skip other users.
        subscriptions=tuple(self._subscriptions)
        workers=tuple(dict.fromkeys(worker for sub in subscriptions
            if (worker:=getattr(sub,'_wait_for_msgs_task',None)) is not None
                and worker is not asyncio.current_task()))
        for sub in subscriptions:
            try:
                async with asyncio.timeout(2):await sub.unsubscribe()
            except Exception:pass
        failed=False
        for connection in tuple(self._clients):
            try:await _close_client(connection)
            except Exception:failed=True
            else:self._clients.remove(connection)
        users=tuple(dict.fromkeys((*workers,*self._handlers,*self._proofs)))
        if users:
            _,pending=await asyncio.wait(users,timeout=8)
            if pending:failed=True
            for original in users:
                if original.done() and not original.cancelled():original.exception()
        if failed:_fail('task_credential_users_not_joined')
        self._subscriptions.clear()

    async def close(self,*,timeout=10):
        self._closed=True
        if self._closing is None or self._closing.done() and self._closing.exception() is not None:
            self._closing=asyncio.create_task(self._finish_close(timeout),name='task-credential-cleanup')
            self._closing.add_done_callback(lambda done:None if done.cancelled() else done.exception())
        await asyncio.wait((self._closing,))
        return self._closing.result()

    async def _finish_close(self,timeout):
        if self._jobs:
            _,pending=await asyncio.wait(tuple(self._jobs),timeout=timeout)
            if pending:_fail('task_credential_users_not_joined')
        await self._cleanup_users()
        self._store.close()
