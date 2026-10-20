"""Real enrolled signing/verification and receiving adapters, with offline broker I/O."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed.code_services import Checkout
from identity import test_capability_admission
from state_owner.artifacts import OwnerArtifacts
from state_owner.test_artifacts import Store, JS
from state_owner.test_ledger import record
from .receiver import CapabilityReceiver
from .resources import RetainedResource
from .workspace import WorkspaceRoot


class AdmittedReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        test_capability_admission.CapabilityAdmissionTests.setUp(self)
        self.original['authorizationDecision']={
            'operationId':self.original['operation']['operationId'], 'decision':'allowed',
            'reason':'current_authority', 'actorRef':self.original['operation']['effectiveActorRef'],
            'contractId':'capability-storage-write'}
    asyncSetUp = test_capability_admission.CapabilityAdmissionTests.asyncSetUp
    request = test_capability_admission.CapabilityAdmissionTests.request
    admit = test_capability_admission.CapabilityAdmissionTests.admit

    def route(self, contract, inputs, *, version=2):
        self.record['state']['grants'][1]['contractId']=contract
        self.js.messages[0].data=canonical_bytes(self.record)
        self.claims.update(contractId=contract,expectedVersion=version,
            payload={'resourceRef':{'id':'task-one','ownerHubId':'hub-one','revision':version},'input':inputs})

    async def append_resource(self, *, artifacts=None, repository=None):
        update=record('resource-update',2,1)
        update['operation']['scope']=copy.deepcopy(self.original['operation']['scope'])
        update['artifacts']=artifacts or []
        update['repository']=repository
        await self.resource.ledger.append(update,expected_sequence=1)

    async def test_outcome_through_admission_requires_original_retained_provenance(self):
        self.route('capability-outcome-query',{'contractId':'capability-storage-write',
            'operationId':self.original['operation']['operationId'],
            'payloadDigest':self.original['operation']['payloadDigest']},version=1)
        grant=copy.deepcopy(self.record['state']['grants'][1])
        grant['ref']={'id':'write-grant','ownerHubId':'hub-one','revision':1}
        grant['contractId']='capability-storage-write'
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        admitted=await self.admit()
        self.assertEqual(admitted.decision.outcome,'allowed')
        response=await self.receiver.handle(admitted.envelope)
        self.assertEqual(strict_loads(response.payload)['outcome'],'committed')
        self.assertEqual(strict_loads(response.payload)['recordRef']['id'],self.original['recordId'])
        self.assertEqual(len(self.resource_js.messages),1)

    async def test_artifact_through_actual_enrolled_admission(self):
        store=Store()
        artifacts=OwnerArtifacts(store,JS(store),bucket='bucket',owner_hub_id='hub-one',
            store_ref={'id':'store','ownerHubId':'hub-one','revision':1},max_bytes=45000)
        reference=await artifacts.upload(b'original-artifact',media_type='text/plain')
        await self.append_resource(artifacts=[reference])
        resource=RetainedResource(self.resource.binding,self.resource.ledger,artifacts=artifacts)
        receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[resource])
        self.addAsyncCleanup(receiver.close)
        self.route('capability-artifact-read',{'digest':reference['digest']})
        admitted=await self.admit()
        self.assertEqual(admitted.decision.outcome,'allowed')
        response=await receiver.handle(admitted.envelope)
        self.assertEqual(base64.b64decode(strict_loads(response.payload)['data']),b'original-artifact')
        store.data=b'corrupt-artifact!'
        with self.assertRaisesRegex(ContractError,'^capability_owner_unavailable$'):
            await receiver.handle(admitted.envelope)
        self.assertEqual(len(self.resource_js.messages),2)

    async def test_artifact_revision_change_during_retrieval_withholds_bytes(self):
        store=Store()
        artifacts=OwnerArtifacts(store,JS(store),bucket='bucket',owner_hub_id='hub-one',
            store_ref={'id':'store','ownerHubId':'hub-one','revision':1},max_bytes=45000)
        reference=await artifacts.upload(b'original-artifact',media_type='text/plain')
        await self.append_resource(artifacts=[reference])
        resource=RetainedResource(self.resource.binding,self.resource.ledger,artifacts=artifacts)
        receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[resource])
        self.addAsyncCleanup(receiver.close)
        self.route('capability-artifact-read',{'digest':reference['digest']})
        admitted=await self.admit()
        retrieve=artifacts.retrieve
        async def changed(ref):
            data=await retrieve(ref)
            update=record('artifact-withdrawn',3,2)
            update['operation']['scope']=copy.deepcopy(self.original['operation']['scope'])
            await resource.ledger.append(update,expected_sequence=2)
            return data
        with patch.object(artifacts,'retrieve',side_effect=changed):
            with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):
                await receiver.handle(admitted.envelope)
        self.assertEqual(len(self.resource_js.messages),3)

    async def test_artifact_denies_before_owner_io_and_rechecks_revocation_after_it(self):
        store=Store()
        artifacts=OwnerArtifacts(store,JS(store),bucket='bucket',owner_hub_id='hub-one',
            store_ref={'id':'store','ownerHubId':'hub-one','revision':1},max_bytes=45000)
        reference=await artifacts.upload(b'original-artifact',media_type='text/plain')
        await self.append_resource(artifacts=[reference])
        resource=RetainedResource(self.resource.binding,self.resource.ledger,artifacts=artifacts)
        receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[resource])
        self.addAsyncCleanup(receiver.close)
        self.route('capability-artifact-read',{'digest':reference['digest']})
        admitted=await self.admit()
        grant=self.record['state']['grants'][1]
        def revoke():
            grant['status']='revoked'
            self.js.messages[0].data=canonical_bytes(self.record)
        revoke()
        with patch.object(resource.ledger,'current',wraps=resource.ledger.current) as current:
            with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await receiver.handle(admitted.envelope)
            current.assert_not_awaited()
        grant['status']='active'
        self.js.messages[0].data=canonical_bytes(self.record)
        original=resource.ledger.current
        async def current_then_revoke():
            result=await original()
            revoke()
            return result
        with patch.object(resource.ledger,'current',side_effect=current_then_revoke), \
                patch.object(artifacts,'retrieve',wraps=artifacts.retrieve) as retrieve:
            with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await receiver.handle(admitted.envelope)
            retrieve.assert_not_awaited()

    async def test_workspace_through_actual_enrolled_admission(self):
        await self.append_resource(repository={'repositoryId':'repo-one','revision':'known-revision',
            'treeDigest':payload_digest({'tree':'fixture'})})
        with tempfile.TemporaryDirectory() as path:
            (Path(path)/'file').write_bytes(b'workspace-data')
            root=WorkspaceRoot(Checkout('repo','repo-one',path,'origin','private-url'))
            resource=RetainedResource(self.resource.binding,self.resource.ledger,workspace=root)
            receiver=CapabilityReceiver(self.service.reader,hub_id='hub-one',resources=[resource])
            try:
                self.route('capability-workspace-read',{'relativePath':'file'})
                admitted=await self.admit()
                self.assertEqual(admitted.decision.outcome,'allowed')
                response=await receiver.handle(admitted.envelope)
                self.assertEqual(base64.b64decode(strict_loads(response.payload)['data']),b'workspace-data')
                (Path(path)/'link').symlink_to(Path(path)/'file')
                self.route('capability-workspace-read',{'relativePath':'link'})
                refused=await self.admit()
                self.assertEqual(refused.decision.outcome,'allowed')
                with self.assertRaisesRegex(ContractError,'^capability_owner_unavailable$'):
                    await receiver.handle(refused.envelope)
            finally:
                await receiver.close()
                root.close()
