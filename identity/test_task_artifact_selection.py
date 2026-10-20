"""Optional task artifact custody preserves default denial and exact pins."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, validate
from identity import test_task_selection as support
from identity.test_authority import ref
from state_owner.artifacts import OwnerArtifacts
from native_security.nats_credentials import service_policy, validate_service, CredentialError
from native_security.test_nats_service_credentials import signed_service, _ArtifactConnection
from nats.js.client import JetStreamContext


class TaskArtifactSelectionTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.TaskSelectionTests.setUp
    selected = support.TaskSelectionTests.selected
    resources = support.TaskSelectionTests.resources
    inputs = support.TaskSelectionTests.inputs

    def configure(self):
        self.value['task']['artifacts'] = {'bucket':'TASK_ARTIFACTS','storeRef':ref('task-artifacts'),
            'maxBytes':1024,'reader':{'transportRef':ref('task-reader'),'grantRef':ref('task-backup-grant'),
                'approvalsByOperation':{'artifact_backup_'+'a'*64:[ref('read-approval')]}}}

    def provider(self):
        return OwnerArtifacts(SimpleNamespace(_name='TASK_ARTIFACTS'),object(),bucket='TASK_ARTIFACTS',
            owner_hub_id='hub-one',store_ref=ref('task-artifacts'),max_bytes=1024)

    async def test_default_denial_and_exact_optional_provider_reader(self):
        selected = self.selected()
        inputs = self.inputs(selected)
        with self.assertRaises(ContractError):
            selected.task_kwargs(**inputs,artifacts=self.provider())
        self.configure()
        selected = self.selected()
        provider = self.provider()
        kwargs = selected.task_kwargs(**inputs,artifacts=provider)
        self.assertIs(kwargs['artifacts'],provider)
        self.assertEqual(kwargs['artifact_reader'],{'transport_ref':ref('task-reader'),
            'grant_ref':ref('task-backup-grant'),
            'approvals_by_operation':{'artifact_backup_'+'a'*64:[ref('read-approval')]}})
        with self.assertRaises(ContractError):
            selected.task_kwargs(**inputs)
        for field, value in (('_bucket','OTHER'),('_owner','other-hub'),('_ref',ref('other-store')),('_max_bytes',2048)):
            with patch.object(provider,field,value), self.assertRaises(ContractError):
                selected.task_kwargs(**inputs,artifacts=provider)
        with patch.object(provider._store,'_name','OTHER'), self.assertRaises(ContractError):
            selected.task_kwargs(**inputs,artifacts=provider)
        self.value['task']['artifacts']['reader'].pop('approvalsByOperation')
        self.assertEqual(self.selected().task_kwargs(**inputs,artifacts=provider)['artifact_reader']['approvals_by_operation'],{})

    async def test_closed_reader_scope_approval_bounds_and_selection_size(self):
        self.configure()
        pristine = copy.deepcopy(self.value)
        changes = [lambda a:a['reader'].update(extra=True),
            lambda a:a['reader']['transportRef'].update(ownerHubId='other-hub'),
            lambda a:a['reader']['grantRef'].update(revision=0),
            lambda a:a['storeRef'].update(ownerHubId='other-hub'),
            lambda a:a.update(bucket='TASK.*'),
            lambda a:a['reader'].update(approvalsByOperation={'arbitrary-op':[ref('read-approval')]}),
            lambda a:a['reader'].update(approvalsByOperation={'artifact_backup_'+'a'*64:[ref('read-approval')]*2}),
            lambda a:a['reader'].update(approvalsByOperation={'artifact_backup_'+'a'*64:[ref('read-'+str(i)) for i in range(33)]}),
            lambda a:a['reader'].update(approvalsByOperation={'artifact_backup_'+format(i,'064x'):[ref('read-approval')] for i in range(1024)})]
        for change in changes:
            self.value = copy.deepcopy(pristine)
            change(self.value['task']['artifacts'])
            with self.assertRaises(ContractError):
                self.selected()
        self.value = pristine
        self.value['task']['ledger']['stream'] = 'OBJ_TASK_ARTIFACTS'
        with self.assertRaises(ContractError):
            self.selected()

    async def test_exact_read_only_object_policy_and_widening_refusal(self):
        before = service_policy(**self.selected().service_policy_inputs('task'))
        self.configure()
        options = self.selected().service_policy_inputs('task')
        policy = service_policy(**options)
        added = {prefix+operation+'.OBJ_TASK_ARTIFACTS'
            for prefix in ('$JS.API.','$JS.enrolled-domain.API.')
            for operation in ('STREAM.INFO','STREAM.MSG.GET')}
        self.assertEqual(set(policy.publish_subjects),set(before.publish_subjects)|added)
        self.assertEqual(policy.subscribe_subjects,before.subscribe_subjects)
        self.assertEqual(policy.response_permissions,before.response_permissions)
        raw, account, user = signed_service(options)
        self.assertEqual(validate_service(raw,account_public_key=account,**options).public_key,user)
        for extra in ('$O.TASK_ARTIFACTS.C.*','$O.TASK_ARTIFACTS.M.*',
                '$JS.API.STREAM.DELETE.OBJ_TASK_ARTIFACTS','$JS.API.STREAM.PURGE.OBJ_TASK_ARTIFACTS',
                '$JS.API.CONSUMER.CREATE.OBJ_TASK_ARTIFACTS','$JS.API.STREAM.MSG.GET.OBJ_OTHER',
                '$JS.OTHER.API.STREAM.INFO.OBJ_TASK_ARTIFACTS','$JS.API.STREAM.MSG.GET.IDENTITY'):
            raw, account, _ = signed_service(options,lambda n:n['pub']['allow'].append(extra))
            with self.assertRaises(CredentialError):
                validate_service(raw,account_public_key=account,**options)
        for missing in added:
            raw, account, _ = signed_service(options,lambda n:n['pub']['allow'].remove(missing))
            with self.assertRaises(CredentialError):
                validate_service(raw,account_public_key=account,**options)

    async def test_new_bucket_and_approval_keys_reject_trailing_line_terminators(self):
        self.configure()
        pristine = copy.deepcopy(self.value)
        validate('application-service-selection',pristine)
        self.selected()
        for ending in ('\n','\r','\r\n','\u2028','\u2029'):
            for field in ('bucket','approval'):
                self.value = copy.deepcopy(pristine)
                artifacts = self.value['task']['artifacts']
                if field == 'bucket':
                    artifacts['bucket'] += ending
                else:
                    artifacts['reader']['approvalsByOperation'] = {
                        'artifact_backup_'+'a'*64+ending:[ref('read-approval')]}
                with self.subTest(field=field,ending=repr(ending)):
                    with self.assertRaises(ContractError):
                        validate('application-service-selection',self.value)
                    with self.assertRaises(ContractError):
                        self.selected()

    async def test_real_object_metadata_and_chunks_fit_read_only_task_policy(self):
        self.configure()
        options = self.selected().service_policy_inputs('task')
        writer_options = {**options,'role':'definitions'}
        writer = _ArtifactConnection(service_policy(**writer_options))
        writer_js = JetStreamContext(writer,domain=options['jetstream_domain'])
        store = await writer_js.object_store('TASK_ARTIFACTS')
        writer_artifacts = OwnerArtifacts(store,writer_js,bucket='TASK_ARTIFACTS',owner_hub_id='hub-one',
            store_ref=ref('task-artifacts'),max_bytes=1024)
        raw = b'retained task artifact'
        reference = await writer_artifacts.upload(raw,media_type='text/plain')
        reader = _ArtifactConnection(service_policy(**options))
        reader.messages = dict(writer.messages)
        reader_js = JetStreamContext(reader,domain=options['jetstream_domain'])
        reader_store = await reader_js.object_store('TASK_ARTIFACTS')
        artifacts = OwnerArtifacts(reader_store,reader_js,bucket='TASK_ARTIFACTS',owner_hub_id='hub-one',
            store_ref=ref('task-artifacts'),max_bytes=1024)
        self.assertEqual(await artifacts.retrieve(reference),raw)
        self.assertTrue(reader.calls)
        self.assertTrue(all('.STREAM.INFO.OBJ_TASK_ARTIFACTS' in s or '.STREAM.MSG.GET.OBJ_TASK_ARTIFACTS' in s for s in reader.calls))
