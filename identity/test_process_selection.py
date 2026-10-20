"""Closed selected Process configuration and exact signed broker credentials."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys

import nkeys
from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes
from execution_owner.test_plans import approved_profile
from native_security.nats_credentials import CredentialError
from .application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from .process_selection import load_connection, load_receiver_seed, load_signer, receiver_policy, state_policy
from .test_authority import ref
from .test_workspace_selection import WorkspaceSelectionTests


def signed_policy(policy,number,*,service):
    account=nkeys.from_seed(nkeys.encode_seed(bytes([1])*32,nkeys.PREFIX_BYTE_ACCOUNT))
    user=nkeys.from_seed(nkeys.encode_seed(bytes([number])*32,nkeys.PREFIX_BYTE_USER))
    try:
        now=int(datetime.now(timezone.utc).timestamp())
        claims={'iss':account.public_key.decode(),'sub':user.public_key.decode(),'iat':now,'exp':now+3600,
            'nats':{'type':'user','version':2,'pub':{'allow':list(policy.publish_subjects)},
                'sub':{'allow':list(policy.subscribe_subjects)}}}
        if service:claims['nats']['resp']=policy.response_permissions
        encode=lambda value:base64.urlsafe_b64encode(canonical_bytes(value)).rstrip(b'=')
        body=encode({'typ':'JWT','alg':'ed25519-nkey'})+b'.'+encode(claims)
        token=body+b'.'+base64.urlsafe_b64encode(account.sign(body)).rstrip(b'=')
        raw=b'-----BEGIN NATS USER JWT-----\n'+token+b'\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n'+user.seed+b'\n------END USER NKEY SEED------\n'
        return raw,account.public_key.decode(),user.public_key.decode()
    finally:account.wipe();user.wipe()


def add_process(test):
    value=test.value;directory=test.root/'process';directory.mkdir(mode=0o700)
    task=value['task'];task['connection']['jetstreamDomain']=None
    scope=copy.deepcopy(task['ledger']['scope']);profile=approved_profile(scope)
    profile.update(workspaceRef=value['workspace']['resourceRef'],consumerRef=task['serviceIdentityRef'])
    def ledger(entity,stream,name):
        pin={key:copy.deepcopy(task['ledger'][key]) for key in ('entityId','scope','stream','streamIdentity','retention','history')}
        pin.update(entityId=entity,stream=stream);pin['history']['path']=str(directory/name)
        return pin
    seed=bytes([31])*32;seed_path=directory/'signer.seed';seed_path.write_bytes(seed);seed_path.chmod(0o600)
    def material(path,raw):return {'path':str(path),'sha256':'sha256:'+hashlib.sha256(raw).hexdigest()}
    signer={'ownerIdentityRef':ref('process-owner-service'),'transportRef':ref('process-transport'),
        'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('='),
        'keyFile':material(seed_path,seed),'inspectionGrantRef':ref('process-inspection-grant'),
        'taskReadGrantRef':ref('process-task-read-grant'),'taskApprovalRefs':[],
        'grants':{name:ref('process-'+name) for name in ('task-credential-prepare','task-credential-deliver',
            'task-credential-observe','task-credential-retire','identity-application-account-resolve','execution-run-record','execution-run-observe')},
        'accountPayload':{'authorityId':'authority-one','profileId':'profile-one','accountRef':ref('application-account'),
            'scope':{**scope,'workspaceId':None},'accountPublicKey':task['credentials']['accountPublicKey']}}
    run={'namespace':'test','stream':'AMX_PROCESS_TEST','inventoryRoot':str(directory/'inventory'),
        'retention':copy.deepcopy(task['ledger']['retention'])}
    state={key:copy.deepcopy(task[key]) for key in ('connection','credentials')}
    state['credentials'].update(path=str(directory/'state.creds'),replyPrefix='_INBOX.process_state_000001')
    pin={'scope':scope,'profile':profile,'executorRef':ref('executor'),'enrollmentIdentityRef':ref('process-admin'),
        'pluginIdentityRef':ref('plugin'),'instanceId':'plugin-one','packageId':'test-plugin',
        'plans':ledger('plan-one','PROCESS_PLANS','plans.sqlite'),
        'credentialsLedger':ledger('credential','PROCESS_CREDENTIALS','credentials.sqlite'),'state':state,
        'receivers':{},'signer':signer,'custodyRoot':str(directory/'credentials-custody'),
        'accountCustodyRoot':str(directory/'account-custody'),'run':run,'networkDestinations':[],
        'docker':{'executable':str(Path(sys.executable).resolve()),'context':'desktop-linux',
            'endpoint':'unix:///tmp/process-selected.sock','engine_id':'selected-engine','server_version':'29.8.2',
            'config_directory':str(directory/'docker'),'image_id':'sha256:'+'a'*64}}
    value['process']=pin
    for index,name in enumerate(('process','outcome'),22):
        payload,receipt=provision_application_service_issuer(directory/(name+'.key'),service_id=name+'-owner',
            profile_id='profile-one',authority_id='authority-one',instance_id=name+'-instance',
            identity={'ref':ref(name+'-service'),'kind':'service','status':'active','principalId':name+'-service','externalIdentity':None},
            issuer_ref=ref(name+'-issuer'),issued_at=test.issuer_start,expires_at=test.issuer_end)
        entry={key:copy.deepcopy(task[key]) for key in ('connection','credentials')}
        entry.update(serviceIdentityRef=ref(name+'-service'),serviceInstanceId=name+'-instance',requestSigningKeyRef=ref('identity-issuer'),
            issuer={'keyFile':{'path':receipt.path,'sha256':receipt.digest},'issuerRef':ref(name+'-issuer'),
                'publicKey':payload['issuers'][0]['record']['publicKey']})
        entry['credentials'].update(path=str(directory/(name+'.creds')),replyPrefix='_INBOX.process_'+name+'_000001')
        pin['receivers'][name]=entry
        raw,account,user=signed_policy(receiver_policy(value,name),index,service=True)
        Path(entry['credentials']['path']).write_bytes(raw);Path(entry['credentials']['path']).chmod(0o600)
        entry['credentials'].update(sha256=material('',raw)['sha256'],accountPublicKey=account,userPublicKey=user)
    raw,account,user=signed_policy(state_policy(value),21,service=False)
    Path(state['credentials']['path']).write_bytes(raw);Path(state['credentials']['path']).chmod(0o600)
    state['credentials'].update(sha256=material('',raw)['sha256'],accountPublicKey=account,userPublicKey=user)
    return pin


class ProcessSelectionTests(WorkspaceSelectionTests):
    def setUp(self):
        super().setUp();add_process(self)

    async def test_closed_process_selection_and_exact_credential_forms(self):
        selected=ApplicationServiceSelection(canonical_bytes(self.value))
        for name in ('state','process','outcome'):
            credential=load_connection(selected.policy,name)
            entry=selected.policy['process']['state'] if name=='state' else selected.policy['process']['receivers'][name]
            self.assertEqual(credential.public_key,entry['credentials']['userPublicKey'])
        self.assertEqual(len(load_signer(selected.policy['process']['signer'])),32)
        self.assertEqual(len(load_receiver_seed(selected.policy,'process')),32)
        self.assertEqual(len(load_receiver_seed(selected.policy,'outcome')),32)
        policy=state_policy(selected.policy)
        self.assertNotIn('$JS.API.>',policy.publish_subjects)
        self.assertEqual(sum('STREAM.CREATE.' in subject for subject in policy.publish_subjects),1)
        self.assertFalse(any('STREAM.UPDATE.' in subject or 'STREAM.DELETE.' in subject for subject in policy.publish_subjects))

    async def test_changed_selection_scope_sources_and_material_aliases_refuse(self):
        for mode in ('task','workspace','scope','consumer','workspace-reference','run','custody','material','credential','domain','command'):
            value=copy.deepcopy(self.value);pin=value['process']
            if mode=='task':value.pop('task')
            elif mode=='workspace':value.pop('workspace')
            elif mode=='scope':pin['scope']['projectId']='another-project'
            elif mode=='consumer':pin['profile']['consumerRef']=ref('another-consumer')
            elif mode=='workspace-reference':pin['profile']['workspaceRef']=ref('another-workspace')
            elif mode=='run':pin['run']['stream']='AMX_PROCESS_OTHER'
            elif mode=='custody':pin['custodyRoot']=value['workspaces'][0]
            elif mode=='material':pin['signer']['keyFile']['path']=value['task']['issuer']['keyFile']['path']
            elif mode=='credential':pin['state']['credentials']['userPublicKey']=value['task']['credentials']['userPublicKey']
            elif mode=='domain':pin['state']['connection']['jetstreamDomain']='OTHER'
            else:pin['command']=['sh','-c','unapproved']
            with self.subTest(mode=mode),self.assertRaises(ContractError):ApplicationServiceSelection(canonical_bytes(value))

    async def test_broadened_state_credential_refuses_even_with_updated_digest(self):
        from native_security.nats_credentials import BoardPublisherPolicy
        selected=ApplicationServiceSelection(canonical_bytes(self.value));policy=state_policy(selected.policy)
        wider=BoardPublisherPolicy(policy.ledger_subject,(*policy.publish_subjects,'$JS.API.>'),policy.subscribe_subjects)
        raw,account,user=signed_policy(wider,21,service=False)
        pin=self.value['process']['state']['credentials'];Path(pin['path']).write_bytes(raw)
        pin.update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),accountPublicKey=account,userPublicKey=user)
        with self.assertRaises(CredentialError):load_connection(ApplicationServiceSelection(canonical_bytes(self.value)).policy,'state')


for _name in dir(WorkspaceSelectionTests):
    if _name.startswith('test_') and _name not in vars(ProcessSelectionTests):setattr(ProcessSelectionTests,_name,None)
