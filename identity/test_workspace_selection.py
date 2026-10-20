"""Selected workspace receiver has exact task, custody and credential pins."""
import copy
import hashlib
from pathlib import Path
import unittest

from agentmux_contracts import ContractError, canonical_bytes
from native_security.nats_credentials import CredentialError, workspace_receiver_policy
from native_security.test_nats_service_credentials import signed_service_policy
from .application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from .test_authority import ref
from .test_task_selection import TaskSelectionTests
from .workspace_selection import load_workspace_credentials, load_workspace_signing_seed, workspace_policy_inputs
from hub.fed.policy import rid_for_remote


def add_workspace(test):
    directory = test.root / 'workspace-service'
    directory.mkdir(mode=0o700)
    payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
        service_id='workspace-owner', profile_id='profile-one', authority_id='authority-one',
        instance_id='workspace-instance', identity={'ref':ref('workspace-service'), 'kind':'service',
            'status':'active', 'principalId':'workspace-service', 'externalIdentity':None},
        issuer_ref=ref('workspace-issuer'), issued_at=test.issuer_start, expires_at=test.issuer_end)
    receiver = {key:copy.deepcopy(test.value['task'][key]) for key in ('connection','credentials')}
    receiver.update(issuer={'keyFile':{'path':receipt.path,'sha256':receipt.digest},
        'issuerRef':ref('workspace-issuer'),'publicKey':payload['issuers'][0]['record']['publicKey']},
        serviceIdentityRef=ref('workspace-service'),serviceInstanceId='workspace-instance',
        requestSigningKeyRef=ref('identity-issuer'))
    receiver['credentials'].update(path=str(directory/'user.creds'),replyPrefix='_INBOX.workspace_service_000001')
    scope = test.value['task']['ledger']['scope']
    policy = workspace_receiver_policy(hub_id='hub-one',scope=scope,
        reply_prefix=receiver['credentials']['replyPrefix'])
    raw, account, user = signed_service_policy(policy)
    Path(receiver['credentials']['path']).write_bytes(raw)
    Path(receiver['credentials']['path']).chmod(0o600)
    receiver['credentials'].update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),
        accountPublicKey=account,userPublicKey=user)
    test.value['workspace'] = dict(receiver=receiver,source={
        'database':{'path':str(test.root/'workspace-hub.db'),'applicationId':0,'userVersion':1},
        'policy':{'path':str(test.root/'workspace-federation.toml'),'sha256':'sha256:'+'a'*64}},
        repository={'localName':'falcon','repositoryId':rid_for_remote('example.invalid/workspace'),
            'normalizedRemote':'example.invalid/workspace'}, checkoutPath=test.value['workspaces'][0],
        localPeer='nick',resourceRef=ref('task-one'))
    return payload


class WorkspaceSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        TaskSelectionTests.setUp(self)
        add_workspace(self)

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    async def test_exact_workspace_receiver_credentials_and_signing_key(self):
        selected = self.selected()
        credential = load_workspace_credentials(selected)
        self.assertEqual(credential.public_key,
            self.value['workspace']['receiver']['credentials']['userPublicKey'])
        self.assertEqual(len(load_workspace_signing_seed(selected)),32)
        policy = workspace_receiver_policy(**workspace_policy_inputs(selected))
        self.assertEqual(policy.publish_subjects,())
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w.workspace-one.capability.workspace-owner.command')
        self.assertEqual(len(policy.subscribe_subjects),2)

    async def test_task_checkout_scope_and_private_material_substitution_refuse(self):
        for change in ('task','resource','checkout','remote','key','inbox','path'):
            value = copy.deepcopy(self.value)
            if change == 'task':value.pop('task')
            elif change == 'resource':value['workspace']['resourceRef']=ref('other-task')
            elif change == 'checkout':value['workspace']['checkoutPath']=str(self.root/'other')
            elif change == 'remote':value['workspace']['repository']['normalizedRemote']='example.invalid/other'
            elif change == 'key':value['workspace']['receiver']['credentials']['userPublicKey']=value['identity']['credentials']['userPublicKey']
            elif change == 'inbox':value['workspace']['receiver']['credentials']['replyPrefix']=value['task']['requesterReplyPrefix']
            else:value['workspace']['receiver']['issuer']['keyFile']['path']=value['task']['issuer']['keyFile']['path']
            with self.subTest(change=change), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(value))

    async def test_broadened_receiver_permissions_refuse_with_matching_file_digest(self):
        policy = workspace_receiver_policy(**workspace_policy_inputs(self.selected()))
        raw, account, user = signed_service_policy(policy,lambda nats:nats.update(pub={'allow':['>']}))
        pin = self.value['workspace']['receiver']['credentials']
        Path(pin['path']).write_bytes(raw)
        pin.update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),accountPublicKey=account,userPublicKey=user)
        with self.assertRaises(CredentialError):
            load_workspace_credentials(self.selected())

    async def test_omitted_workspace_keeps_existing_selection(self):
        self.value.pop('workspace')
        self.assertNotIn('workspace',self.selected().policy)
