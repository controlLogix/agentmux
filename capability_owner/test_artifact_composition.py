"""Actual selected task/artifact owners with controlled broker I/O."""
import asyncio
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims
from dashboard import test_application_service_host as host_support
from application_service_host import ApplicationServiceHost, ApplicationServiceFailure
from identity.application_service_selection import ApplicationServiceSelection
from identity.test_authority import ref
from identity.test_artifact_selection import add_artifact
from identity.test_task_selection import TaskSelectionTests
from state_owner.backup_host import BackupHost
from state_owner.ledger import owner_subject
from state_owner.test_ledger import record


class ArtifactCompositionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        TaskSelectionTests.setUp(self)
        self.payloads.append(add_artifact(self))
        self.value['task']['artifacts']['bucket']='bucket'
        task = self.value['task']
        issuer = {'ref':task['issuer']['issuerRef'], 'identityRef':ref('task-service'),
            'status':'active', 'instanceId':'task-instance', 'publicKey':task['issuer']['publicKey'],
            'issuedAt':self.issuer_start, 'expiresAt':self.issuer_end}
        proof = {'purpose':'agentmux-enrollment-possession-v1', 'profileId':'profile-one',
            'authorityId':'authority-one', 'credential':issuer}
        selected = ApplicationServiceSelection(canonical_bytes(self.value))
        self.payloads.append({'authorityId':'authority-one', 'identity':{
            'ref':ref('task-service'), 'kind':'service', 'status':'active',
            'principalId':'task-service', 'externalIdentity':None},
            'issuers':[{'record':issuer,'proof':sign_claims(proof,selected.load_signing_seed('task'))}],
            'transports':[]})
        host_support.HostComposition.prepare_services(self)
        selected = self.value['task']
        backup = selected['backup']
        host = BackupHost(*(backup[key] for key in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'], binding=self.selection.binding('task'),
            stream_identity=self.selection.stream_identity('task'))
        host.enroll_key(backup['keyId'])
        original = record('artifact-task')
        original.update(effects=[],artifacts=[],repository=None,state={'taskId':'task-one','status':'ready',
            'assignmentEpoch':0,'reservation':None})
        original['operation']['scope']=copy.deepcopy(selected['ledger']['scope'])
        self.original = canonical_bytes(original)
        connection = self.clients[2]
        connection.max_payload=1_048_576
        connection.js._nc=connection
        connection.js._prefix='$JS.enrolled-domain.API'
        connection.js.objects._js=connection.js
        connection.js.objects._name='bucket'
        connection.js.messages=[SimpleNamespace(subject=owner_subject(self.selection.binding('task')),
            seq=1,data=self.original)]
        receiver_connection=host_support.Client(connection.js)
        receiver_connection.max_payload=98304
        self.clients.append(receiver_connection)

    async def asyncSetUp(self):
        self.host=ApplicationServiceHost(self.selection,browser_port=0)
        self.addAsyncCleanup(self.host.close)

    async def start(self):
        with patch('application_service_host.new_client',side_effect=self.clients) as create:
            try:
                await self.host.start()
            except ApplicationServiceFailure:
                raise self.host._startup.exception()
        self.assertEqual(create.call_count,4)
        self.host.check_health()
        return self.host._artifact._resource

    async def test_startup_borrows_task_custody_and_never_uses_backup_authorization(self):
        resource=await self.start()
        task=self.host._task
        self.assertIs(resource.ledger,task.ledger)
        self.assertIs(resource.artifacts,task._artifact_custody._artifacts)
        reference=await resource.artifacts.upload(b'original task artifact',media_type='text/plain')
        update=record('artifact-attached',2,1)
        update.update(effects=[],repository=None,artifacts=[reference],state={
            'taskId':'task-one','status':'ready','assignmentEpoch':0,'reservation':None})
        update['operation']['scope']=copy.deepcopy(self.value['task']['ledger']['scope'])
        await task.ledger.append(update,expected_sequence=1,completion_records=0)
        receiver=self.host._artifact._service._receiver
        with patch.object(task._artifact_custody,'retrieve',side_effect=AssertionError('backup grant is not plugin authority')):
            result,contract=await receiver._read('capability-artifact-read',{
                'resourceRef':dict(ref('task-one'),revision=2),'input':{'digest':reference['digest']}},resource)
        import base64
        self.assertEqual(base64.b64decode(result['data']),b'original task artifact')
        self.assertEqual(contract,'capability-content-reply')
        self.assertEqual(self.clients[2].js.messages[0].data,self.original)
        self.assertEqual(len(self.clients[2].js.messages),2)
        with patch.object(resource.artifacts,'_ref',ref('wrong-store')),self.assertRaises(ContractError):
            receiver.check_current(ref('task-one'))
        with patch.object(task,'_closed',True),self.assertRaises(ContractError):
            receiver.check_current(ref('task-one'))

    async def test_close_joins_original_read_before_releasing_task_and_connections(self):
        resource=await self.start()
        receiver=self.host._artifact._service._receiver
        entered,release=asyncio.Event(),asyncio.Event()
        async def retrieve(reference):
            entered.set()
            await release.wait()
            return b'retained'
        closing=None
        try:
            with patch.object(resource.artifacts,'retrieve',side_effect=retrieve):
                read=asyncio.create_task(receiver._artifact_read(resource,{}))
                await asyncio.wait_for(entered.wait(),2)
                read.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await read
                closing=asyncio.create_task(self.host.close())
                await asyncio.sleep(.05)
                self.assertFalse(closing.done())
                self.assertIsNone(self.host._task._closing)
                self.assertTrue(self.clients[2].is_connected)
                release.set()
                await closing
            self.assertTrue(self.host._task._closed)
            self.assertFalse(receiver._workers)
            self.assertFalse(any(client.is_connected for client in self.clients))
        finally:
            release.set()
            if closing is not None:
                await closing

    async def test_wrong_selected_object_store_refuses_startup_and_closes_partial_owners(self):
        self.clients[2].js.objects._name='OTHER'
        with patch('application_service_host.new_client',side_effect=self.clients),self.assertRaises(ApplicationServiceFailure):
            await self.host.start()
        await self.host.close()
        self.assertIsNone(self.host._task)
        self.assertFalse(any(client.is_connected for client in self.clients))
