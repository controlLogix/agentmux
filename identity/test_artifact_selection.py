"""Artifact reads use a separate receiver bound to existing task custody."""
import copy
import hashlib
from pathlib import Path
import unittest

from agentmux_contracts import ContractError, canonical_bytes
from native_security.nats_credentials import CredentialError, artifact_receiver_policy
from native_security.test_nats_service_credentials import signed_service_policy
from .application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from .artifact_selection import load_artifact_credentials, load_artifact_signing_seed, artifact_policy_inputs
from .test_authority import ref
from .test_task_selection import TaskSelectionTests
from .test_task_artifact_selection import TaskArtifactSelectionTests


def add_artifact(test):
    TaskArtifactSelectionTests.configure(test)
    directory = test.root / 'artifact-service'
    directory.mkdir(mode=0o700)
    payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
        service_id='artifact-owner', profile_id='profile-one', authority_id='authority-one',
        instance_id='artifact-instance', identity={'ref':ref('artifact-service'), 'kind':'service',
            'status':'active', 'principalId':'artifact-service', 'externalIdentity':None},
        issuer_ref=ref('artifact-issuer'), issued_at=test.issuer_start, expires_at=test.issuer_end)
    receiver = {key:copy.deepcopy(test.value['task'][key]) for key in ('connection','credentials')}
    receiver.update(issuer={'keyFile':{'path':receipt.path,'sha256':receipt.digest},
        'issuerRef':ref('artifact-issuer'),'publicKey':payload['issuers'][0]['record']['publicKey']},
        serviceIdentityRef=ref('artifact-service'), serviceInstanceId='artifact-instance',
        requestSigningKeyRef=ref('identity-issuer'))
    receiver['credentials'].update(path=str(directory/'user.creds'),replyPrefix='_INBOX.artifact_service_000001')
    policy = artifact_receiver_policy(hub_id='hub-one',scope=test.value['task']['ledger']['scope'],
        reply_prefix=receiver['credentials']['replyPrefix'])
    raw, account, user = signed_service_policy(policy)
    Path(receiver['credentials']['path']).write_bytes(raw)
    Path(receiver['credentials']['path']).chmod(0o600)
    receiver['credentials'].update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),
        accountPublicKey=account,userPublicKey=user)
    test.value['artifact'] = dict(receiver=receiver,resourceRef=ref('task-one'))
    return payload


class ArtifactSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        TaskSelectionTests.setUp(self)
        add_artifact(self)

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    async def test_exact_receiver_has_no_direct_ledger_or_object_access(self):
        selected = self.selected()
        self.assertEqual(load_artifact_credentials(selected).public_key,
            self.value['artifact']['receiver']['credentials']['userPublicKey'])
        self.assertEqual(len(load_artifact_signing_seed(selected)),32)
        policy = artifact_receiver_policy(**artifact_policy_inputs(selected))
        self.assertEqual(policy.publish_subjects,())
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w.workspace-one.capability.artifact-owner.command')
        self.assertEqual(len(policy.subscribe_subjects),2)

    async def test_missing_custody_wrong_resource_or_shared_private_material_refuse(self):
        for change in ('task','custody','resource','key','inbox','path','extra'):
            value = copy.deepcopy(self.value)
            if change == 'task':value.pop('task')
            elif change == 'custody':value['task'].pop('artifacts')
            elif change == 'resource':value['artifact']['resourceRef']=ref('other-task')
            elif change == 'key':value['artifact']['receiver']['credentials']['userPublicKey']=value['identity']['credentials']['userPublicKey']
            elif change == 'inbox':value['artifact']['receiver']['credentials']['replyPrefix']=value['task']['requesterReplyPrefix']
            elif change == 'path':value['artifact']['receiver']['issuer']['keyFile']['path']=value['task']['issuer']['keyFile']['path']
            else:value['artifact']['storeRef']=ref('other-store')
            with self.subTest(change=change), self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(value))

    async def test_broadened_receiver_refuses_even_with_matching_file_digest(self):
        for permission in ('$JS.API.STREAM.MSG.GET.TASK','$JS.API.STREAM.MSG.GET.OBJ_TASK_ARTIFACTS','>'):
            policy = artifact_receiver_policy(**artifact_policy_inputs(self.selected()))
            raw, account, user = signed_service_policy(policy,lambda nats:nats.update(pub={'allow':[permission]}))
            pin = self.value['artifact']['receiver']['credentials']
            Path(pin['path']).write_bytes(raw)
            pin.update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),accountPublicKey=account,userPublicKey=user)
            with self.subTest(permission=permission), self.assertRaises(CredentialError):
                load_artifact_credentials(self.selected())

    async def test_omission_preserves_existing_task_selection(self):
        self.value.pop('artifact')
        self.assertNotIn('artifact',self.selected().policy)
