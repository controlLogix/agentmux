"""Optional task enrollment pins identity, custody, signing and broker access."""
import base64
import binascii
import copy
import hashlib
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agentmux_contracts import ContractError, canonical_bytes
from identity import test_application_service_selection as fixtures
from identity.application_service_selection import ApplicationServiceSelection, provision_application_service_issuer
from identity.ingress import EnrolledIngress
from identity.authority import LedgerAuthorityReader
from identity.service import IdentityService
from identity.test_authority import ref
from state_owner.history import OwnerHistory
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.ledger import OwnerLedger, StreamIdentity
from native_security.nats_credentials import service_policy, validate_service, CredentialError
from native_security.test_nats_service_credentials import signed_service


class TaskSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.ServiceSelectionTests.setUp(self)
        directory = self.root / 'task'
        directory.mkdir(mode=0o700)
        service = copy.deepcopy(self.value['identity'])
        payload, receipt = provision_application_service_issuer(directory / 'issuer.key',
            service_id='task-owner', profile_id='profile-one', authority_id='authority-one', instance_id='task-instance',
            identity={'ref':ref('task-service'), 'kind':'service', 'status':'active',
                'principalId':'task-service', 'externalIdentity':None},
            issuer_ref=ref('task-issuer'), issued_at=self.issuer_start, expires_at=self.issuer_end)
        service['issuer'] = {'keyFile':{'path':receipt.path, 'sha256':receipt.digest},
            'issuerRef':ref('task-issuer'), 'publicKey':payload['issuers'][0]['record']['publicKey']}
        key = bytes([160]) + bytes([4])*32
        service['credentials'].update(path=str(directory/'user.creds'), userPublicKey=base64.b32encode(
            key+binascii.crc_hqx(key,0).to_bytes(2,'little')).decode(), replyPrefix='_INBOX.task_service_00000001')
        service['ledger'].update(entityId='task-one', stream='TASK')
        service['ledger']['scope'].update(projectId='project-one', workspaceId='workspace-one')
        service['ledger']['history']['path'] = str(directory/'history.sqlite')
        service['ledger']['checkpoint'] = {'path':str(directory/'checkpoint'), 'commitRef':ref('task-checkpoint')}
        for field in ('backupDirectory','inventoryDirectory','keyDirectory'):
            path = directory/field
            path.mkdir(mode=0o700)
            service['backup'][field] = str(path)
        service.update(serviceIdentityRef=ref('task-service'),serviceInstanceId='task-instance',
            requesterReplyPrefix='_INBOX.task_requester_000001')
        self.value['task'] = service

    def selected(self):
        return ApplicationServiceSelection(canonical_bytes(self.value))

    def resources(self, selected, role):
        service = selected.service(role)
        history = OwnerHistory(service['ledger']['history']['path'],selected.binding(role),
            stream_identity=selected.stream_identity(role))
        self.addCleanup(history.close)
        backup = service['backup']
        host = BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'],binding=selected.binding(role),stream_identity=selected.stream_identity(role))
        return history, host

    def inputs(self, selected):
        history, backup = self.resources(selected,'identity')
        connection = SimpleNamespace(jetstream=Mock(return_value=object()))
        identity = IdentityService(connection, **selected.identity_kwargs(history=history,
            checkpoint_committed=lambda receipt:None, signing_seed=selected.load_signing_seed('identity'),backup_host=backup))
        history, backup = self.resources(selected,'task')
        ledger = selected.service('task')['ledger']
        checkpoint = CheckpointHost(ledger['checkpoint']['path'],stream=ledger['stream'],
            commit_ref=ledger['checkpoint']['commitRef'],binding=selected.binding('task'),stream_identity=selected.stream_identity('task'))
        return dict(authority=identity.reader,ingress=identity.ingress,history=history,
            signing_seed=selected.load_signing_seed('task'),checkpoint_host=checkpoint,backup_host=backup)

    async def test_optional_task_preserves_old_selection_and_binds_actual_resources(self):
        original = copy.deepcopy(self.value)
        del self.value['task']
        with self.assertRaises(ContractError):
            self.selected().service('task')
        self.value = original
        selected = self.selected()
        inputs = self.inputs(selected)
        kwargs = selected.task_kwargs(**inputs)
        self.assertIs(kwargs['authority'],inputs['authority'])
        self.assertIs(kwargs['ingress'],inputs['ingress'])
        self.assertIs(kwargs['history'],inputs['history'])
        self.assertIs(kwargs['checkpoint_host'],inputs['checkpoint_host'])
        self.assertIs(kwargs['backup_host'],inputs['backup_host'])
        self.assertEqual((kwargs['binding'].owner_domain,kwargs['binding'].entity_kind),('task','task'))
        self.assertEqual(kwargs['issuer_ref'],ref('task-issuer'))
        self.assertEqual(kwargs['service_identity_ref'],ref('task-service'))
        self.assertEqual(kwargs['service_instance_id'],'task-instance')
        self.assertEqual(kwargs['requester_reply_prefix'],'_INBOX.task_requester_000001')
        self.assertEqual(kwargs['jetstream_domain'],'enrolled-domain')
        self.assertEqual(kwargs['account_public_key'],self.value['task']['credentials']['accountPublicKey'])
        from state_owner.task_host import TaskHost
        connection = SimpleNamespace(jetstream=Mock(return_value=object()))
        host = TaskHost.from_enrolled_host(connection, **kwargs)
        self.assertIs(host.owner._authority, inputs['authority'])
        self.assertIs(host.service.ingress, inputs['ingress'])
        self.assertTrue(host.ledger.completion_budget_required)
        self.assertEqual(host.subject,service_policy(**selected.service_policy_inputs('task')).command_subject)
        connection.jetstream.assert_called_once_with(domain='enrolled-domain')

    async def test_protected_selection_readback_and_exact_signed_credentials(self):
        options = self.selected().service_policy_inputs('task')
        raw, account, user = signed_service(options)
        pin = self.value['task']['credentials']
        path = Path(pin['path'])
        path.write_bytes(raw)
        path.chmod(0o600)
        pin.update(sha256='sha256:'+hashlib.sha256(raw).hexdigest(),accountPublicKey=account,userPublicKey=user)
        selected = fixtures.ServiceSelectionTests.load(self)
        self.assertEqual(selected.policy,self.value)
        result = selected.load_service_credentials('task',protected_host_account=fixtures.protected_host())
        self.assertEqual(result.public_key,user)
        path.write_bytes(raw+b'changed')
        with self.assertRaises(ContractError):
            selected.load_service_credentials('task',protected_host_account=fixtures.protected_host())

    async def test_substituted_identity_and_custody_refuse(self):
        selected = self.selected()
        inputs = self.inputs(selected)
        for field in ('authority','ingress','history','checkpoint_host','backup_host'):
            with self.subTest(field=field), self.assertRaises(ContractError):
                selected.task_kwargs(**{**inputs,field:object()})
        another = copy.copy(inputs['authority'])
        ingress = EnrolledIngress(another,issuer_ref=ref('identity-issuer'),signing_seed=selected.load_signing_seed('identity'))
        with self.assertRaises(ContractError):
            selected.task_kwargs(**{**inputs,'ingress':ingress})
        inputs['checkpoint_host']._ref = canonical_bytes(ref('other-checkpoint'))
        with self.assertRaises(ContractError):
            selected.task_kwargs(**inputs)

    async def test_actual_alternate_identity_stream_is_not_the_selected_source(self):
        selected = self.selected()
        inputs = self.inputs(selected)
        original = inputs['authority']._ledger
        alternate = OwnerLedger(original._js, stream='OTHER_IDENTITY', subject=original._subject,
            binding=original._binding, retention=original._retention, stream_identity=original._identity,
            history=original._history, require_completion_budget=True)
        authority = LedgerAuthorityReader(alternate, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        ingress = EnrolledIngress(authority, issuer_ref=ref('identity-issuer'),
            signing_seed=selected.load_signing_seed('identity'))
        with self.assertRaises(ContractError):
            selected.task_kwargs(**{**inputs,'authority':authority,'ingress':ingress})

    async def test_identity_source_creation_history_floor_and_signer_substitutions_refuse(self):
        self.value['identity']['ledger']['streamIdentity']['minimumSequence'] = 3
        selected = self.selected()
        inputs = self.inputs(selected)
        ledger = inputs['authority']._ledger
        history = ledger._history
        source = selected.stream_identity('identity')
        mutations = [(ledger,'_identity',StreamIdentity(source.created+timedelta(seconds=1),3)),
            (ledger,'_identity',StreamIdentity(source.created,2)),
            (ledger,'_minimum_sequence',2), (ledger,'_history',None),
            (ledger,'_subject','other.subject'),
            (history,'_path',self.root/'other-history.sqlite'),
            (history,'_max_records',history._max_records-1),
            (history,'_max_bytes',history._max_bytes-1),
            (history,'_source_identity',StreamIdentity(source.created+timedelta(seconds=1),3)),
            (history,'_source_identity',StreamIdentity(source.created,2))]
        for target, field, value in mutations:
            with self.subTest(field=field), patch.object(target,field,value), self.assertRaises(ContractError):
                selected.task_kwargs(**inputs)
        for issuer, seed in ((ref('other-issuer'),selected.load_signing_seed('identity')),
                             (ref('identity-issuer'),b'x'*32)):
            ingress = EnrolledIngress(inputs['authority'],issuer_ref=issuer,signing_seed=seed)
            with self.assertRaises(ContractError):
                selected.task_kwargs(**{**inputs,'ingress':ingress})
        ledger.require_recovery_identity(StreamIdentity(source.created,5))
        result = selected.task_kwargs(**inputs)
        self.assertIs(result['authority'],inputs['authority'])
        self.assertIs(result['ingress'],inputs['ingress'])
        with patch.object(history,'_source_identity',StreamIdentity(source.created,6)):
            with self.assertRaises(ContractError):
                selected.task_kwargs(**inputs)
            ledger.require_recovery_identity(StreamIdentity(source.created,6))
            self.assertIs(selected.task_kwargs(**inputs)['authority'],inputs['authority'])

    async def test_private_paths_signer_and_reply_pins_refuse(self):
        pristine = copy.deepcopy(self.value)
        changes = [lambda t: t.update(serviceIdentityRef=ref('task-service')|{'ownerHubId':'other-hub'}),
            lambda t: t.update(serviceInstanceId='bad.instance'),
            lambda t: t.update(requesterReplyPrefix=t['credentials']['replyPrefix']),
            lambda t: t.update(requesterReplyPrefix='_INBOX.>'),
            lambda t: t['ledger']['history'].update(path=self.value['workspaces'][0]+'/history.sqlite'),
            lambda t: t['backup'].update(keyDirectory=t['backup']['backupDirectory']),
            lambda t: t['issuer'].update(publicKey=self.value['identity']['issuer']['publicKey']),
            lambda t: t.update(artifacts={'bucket':'OTHER'})]
        for change in changes:
            self.value = copy.deepcopy(pristine)
            change(self.value['task'])
            with self.assertRaises(ContractError):
                self.selected()
        self.value = pristine
        selected = self.selected()
        with self.assertRaises(ContractError):
            selected.task_kwargs(**{**self.inputs(selected),'signing_seed':b'x'*32})

    async def test_exact_task_broker_scope_and_response_budget(self):
        options = self.selected().service_policy_inputs('task')
        policy = service_policy(**options)
        self.assertEqual(policy.command_subject,'amx.v1.h.hub-one.o.org-one.p.project-one.w.workspace-one.task.task-one.command')
        self.assertEqual(policy.ledger_subject,'amx.v1.h.hub-one.o.org-one.p.project-one.w.workspace-one.ledger.task.task-one')
        expected = [policy.ledger_subject]
        for prefix in ('$JS.API.','$JS.enrolled-domain.API.'):
            expected.extend((prefix+'STREAM.INFO.TASK',prefix+'STREAM.MSG.GET.TASK'))
        self.assertEqual(policy.publish_subjects,tuple(sorted(expected)))
        self.assertEqual(set(policy.subscribe_subjects),{policy.command_subject,options['reply_prefix']+'.>'})
        self.assertEqual(policy.response_permissions,{'max':1,'ttl':8_000_000_000})
        raw, account, user = signed_service(options)
        self.assertEqual(validate_service(raw,account_public_key=account,**options).public_key,user)
        for extra in ('$JS.API.STREAM.MSG.GET.IDENTITY','$JS.API.STREAM.INFO.IDENTITY',
                      '$JS.API.STREAM.CREATE.TASK','$JS.API.CONSUMER.CREATE.TASK',
                      '$JS.OTHER.API.STREAM.INFO.TASK','$O.TASK.C.*','_INBOX.>',policy.command_subject):
            raw, account, _ = signed_service(options,lambda n:n['pub']['allow'].append(extra))
            with self.assertRaises(CredentialError):
                validate_service(raw,account_public_key=account,**options)
        for change in (lambda n:n['resp'].update(max=2),lambda n:n['resp'].update(ttl=8_000_000_001),
                       lambda n:n['resp'].update(ttl=5_000_000_000),
                       lambda n:n['sub']['allow'].append(policy.ledger_subject)):
            raw, account, _ = signed_service(options,change)
            with self.assertRaises(CredentialError):
                validate_service(raw,account_public_key=account,**options)
        self.assertNotIn('artifact_bucket',options)
