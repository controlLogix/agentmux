"""Protected selection and exact broker permissions for approved Process calls."""
import base64
from datetime import datetime, timezone
import os
from pathlib import Path

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from nacl.signing import SigningKey
from native_security.nats_credentials import BoardPublisherPolicy, ServicePolicy, _validate, storage_receiver_policy
from state_owner.ledger import OwnerBinding, owner_subject
from state_owner.retention import Retention
from .authority import _active, _indexes, _key
from .secret_selection import load_material, load_signer


def fail():raise ContractError('application_process_selection_invalid') from None


def retention(pin):return Retention(pin['maxBytes'],pin['reserveBytes'],pin['replicas'])


def ledger_binding(value,pin,domain,kind):
    return OwnerBinding(value['kernelScope']['hubId'],domain,pin['entityId'],kind,canonical_bytes(pin['scope']))


def state_policy(value):
    pin=value['process'];connection=pin['state']['connection'];credential=pin['state']['credentials']
    if connection['jetstreamDomain'] is not None:fail()
    bindings=(ledger_binding(value,pin['plans'],'execution-plans','approved-execution-plan'),
        ledger_binding(value,pin['credentialsLedger'],'task-credentials','effect'))
    execution=owner_subject(OwnerBinding(value['kernelScope']['hubId'],'execution','selected','attempt',canonical_bytes(pin['scope'])))
    subjects=[owner_subject(bindings[1]),execution.removesuffix('.selected')+'.*']
    for stream in (pin['plans']['stream'],pin['credentialsLedger']['stream'],pin['run']['stream']):
        subjects.extend('$JS.API.'+method+'.'+stream for method in ('STREAM.INFO','STREAM.MSG.GET'))
    subjects.append('$JS.API.STREAM.CREATE.'+pin['run']['stream'])
    return BoardPublisherPolicy(subjects[0],tuple(sorted(subjects)),(credential['replyPrefix']+'.>',))


def receiver_policy(value,name):
    if name not in ('process','outcome'):fail()
    pin=value['process'];receiver=pin['receivers'][name]
    base=storage_receiver_policy(hub_id=value['kernelScope']['hubId'],scope=pin['scope'],
        service_id='outcome-owner',reply_prefix=receiver['credentials']['replyPrefix'])
    command=base.command_subject.replace('.outcome-owner.command','.'+name+'-owner.command')
    return ServicePolicy('storage',command,'',(),tuple(sorted((command,receiver['credentials']['replyPrefix']+'.>'))))


def check_process_selection(value):
    pin=value.get('process')
    if pin is None:return
    from .application_service_selection import _outside
    from .workspace_selection import _materials
    validate('process-selection',pin)
    task,workspace=value.get('task'),value.get('workspace')
    profile=pin['profile'];hub=value['kernelScope']['hubId']
    if (task is None or workspace is None or pin['scope']['projectId'] is None
            or pin['scope']!=task['ledger']['scope'] or profile['scope']!=pin['scope']
            or profile['profileId']!=value['kernelScope']['profileId']
            or profile['workspaceRef']!=workspace['resourceRef']
            or profile['consumerRef']!=task['serviceIdentityRef']
            or task['connection']['jetstreamDomain'] is not None
            or pin['run']['stream']!='AMX_PROCESS_'+pin['run']['namespace'].upper()
            or pin['credentialsLedger']['entityId']!=profile['credentialRef']['id']
            or pin['executorRef']['revision']<1 or profile['limits']['offlineSeconds']>profile['limits']['maxSeconds']):fail()
    streams=[pin['plans']['stream'],pin['credentialsLedger']['stream'],pin['run']['stream']]
    if len(set(streams))!=3:fail()
    for ledger in (pin['plans'],pin['credentialsLedger']):
        if ledger['scope']!=pin['scope']:fail()
        retention(ledger['retention'])
    retention(pin['run']['retention']);state_policy(value)
    from execution_owner.network import HTTPSDestination, SelectedNetwork
    destinations=[HTTPSDestination(canonical_bytes(item['reference']),item['host'],item['address'],
        item['port'],item['path'],item['rootsPEM']) for item in pin['networkDestinations']]
    SelectedNetwork(profile['network']['profileRef'],destinations).check(profile)
    def refs(item):
        if type(item) is dict:
            if set(item)=={'id','ownerHubId','revision'}:yield item
            else:
                for child in item.values():yield from refs(child)
        elif type(item) is list:
            for child in item:yield from refs(child)
    if any(ref['ownerHubId']!=hub or ref['revision']<1 for ref in refs(pin)):fail()
    account=pin['signer']['accountPayload']
    if (account['profileId']!=profile['profileId'] or account['authorityId']!=value['authorityId']
            or account['scope']!={**pin['scope'],'workspaceId':None}
            or account['accountPublicKey']!=task['credentials']['accountPublicKey']):fail()
    private=[pin['custodyRoot'],pin['accountCustodyRoot'],pin['run']['inventoryRoot'],
        pin['signer']['keyFile']['path'],pin['plans']['history']['path'],pin['credentialsLedger']['history']['path'],
        pin['state']['credentials']['path']]
    credentials=[pin['state']['credentials']]
    existing=[p for key,p in value.items() if key!='process']
    other_materials=[path for item in existing for path in _materials(item)]
    for name,receiver in pin['receivers'].items():
        receiver_policy(value,name)
        if receiver['requestSigningKeyRef']!=value['identity']['issuer']['issuerRef']:fail()
        private.extend((receiver['credentials']['path'],receiver['issuer']['keyFile']['path']))
        credentials.append(receiver['credentials'])
    for path in private:_outside(path,value['workspaces'])
    resolved=list(map(lambda p:Path(os.path.realpath(p)),private))
    for index,path in enumerate(resolved):
        if any(path.is_relative_to(other) or other.is_relative_to(path) for other in [*resolved[index+1:],*other_materials]):fail()
    if len({c['userPublicKey'] for c in credentials})!=3 or len({c['replyPrefix'] for c in credentials})!=3:fail()
    other_credentials=[]
    def collect(item):
        if type(item) is dict:
            if {'userPublicKey','replyPrefix'}<=set(item):other_credentials.append(item)
            for child in item.values():collect(child)
        elif type(item) is list:
            for child in item:collect(child)
    for item in existing:collect(item)
    if any(c['userPublicKey']==other['userPublicKey'] or c['replyPrefix']==other['replyPrefix']
        for c in credentials for other in other_credentials):fail()


def load_connection(value,name):
    pin=value['process'];entry=pin['state'] if name=='state' else pin['receivers'][name]
    policy=state_policy(value) if name=='state' else receiver_policy(value,name)
    credential=entry['credentials']
    admitted=_validate(load_material(credential),account_public_key=credential['accountPublicKey'],
        publish_subjects=(),subscribe_subjects=(),**({'publisher':policy} if name=='state' else {'service':policy}))
    if admitted.public_key!=credential['userPublicKey']:fail()
    return admitted


def load_receiver_seed(value,name):
    receiver=value['process']['receivers'][name]
    key=strict_loads(load_material(receiver['issuer']['keyFile']));validate('application-service-key',key)
    expected={'serviceId':name+'-owner','hubId':value['kernelScope']['hubId'],'profileId':value['kernelScope']['profileId'],
        'authorityId':value['authorityId'],'issuerRef':receiver['issuer']['issuerRef']}
    if any(key[k]!=v for k,v in expected.items()):fail()
    seed=base64.b64decode(key['seed'],validate=True)
    if len(seed)!=32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')!=receiver['issuer']['publicKey']:fail()
    return seed


async def check_process_authority(selection,identity):
    reader,_=selection.check_storage_identity_source(identity)
    snapshot=await reader.current();selection.check_storage_identity_source(identity)
    record=strict_loads(snapshot.record);index=_indexes(record['state'],record['ownerHubId']);now=datetime.now(timezone.utc)
    pin=selection.policy['process']
    def current(collection,reference):
        item=index[collection].get(_key(reference))
        if item is None or not _active(item,now):fail()
        return item
    if current('identities',pin['pluginIdentityRef'])['kind']!='plugin':fail()
    signer=pin['signer'];transport=current('transports',signer['transportRef'])
    if (current('identities',signer['ownerIdentityRef'])['kind']!='service'
            or transport['identityRef']!=signer['ownerIdentityRef'] or transport['publicKey']!=signer['publicKey']
            or transport['issuerRef']!=selection.policy['identity']['issuer']['issuerRef']):fail()
    for receiver in pin['receivers'].values():
        principal=current('identities',receiver['serviceIdentityRef']);issuer=current('issuers',receiver['issuer']['issuerRef'])
        if (principal['kind']!='service' or issuer['identityRef']!=principal['ref']
                or issuer['instanceId']!=receiver['serviceInstanceId'] or issuer['publicKey']!=receiver['issuer']['publicKey']):fail()
    return reader
