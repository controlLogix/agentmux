"""Offline receiver controls. Internal I/O tests do not qualify current authority."""
import base64
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthorityReader
from identity.test_authority import fixture
from sdk.python.tests.test_contracts import NOW, SEED
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import StreamIdentity
from state_owner.retention import Retention
from state_owner.test_artifacts import Store, JS
from state_owner.test_ledger import BINDING, CREATED, FakeJetStream, record
from .receiver import CapabilityReceiver
from .resources import RetainedResource


class ReceiverTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.policy = Retention(2097152, 262144)
        self.js = FakeJetStream(self.policy)
        self.resource = RetainedResource.open_existing(self.js, binding=BINDING, stream='OWNER',
            stream_identity=StreamIdentity(CREATED, 0), retention=self.policy)
        self.authority_record, self.envelope = fixture()
        class AuthorityJS:
            async def get_msg(inner, *args, **kwargs):
                return SimpleNamespace(subject='identity.owner', seq=1,
                    data=canonical_bytes(self.authority_record))
        self.reader = AuthorityReader(AuthorityJS(), stream='IDENTITY', subject='identity.owner',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        self.receiver = CapabilityReceiver(self.reader, hub_id='hub-one', resources=[self.resource])
        self.addAsyncCleanup(self.receiver.close)
        self.ref = {'id':'task-one', 'ownerHubId':'hub-one', 'revision':1}
        self.original = record()
        self.original['authorizationDecision'] = {
            'operationId':self.original['operation']['operationId'], 'decision':'allowed',
            'reason':'current_authority', 'actorRef':self.original['operation']['effectiveActorRef'],
            'contractId':'capability-storage-write'}
        self.original['state']['unknownFutureField'] = {'unchanged':['a', 42]}
        await self.resource.ledger.append(self.original, expected_sequence=0)

    async def test_storage_preserves_complete_record_and_refuses_stale_revision(self):
        result, contract = await self.receiver._read('capability-storage-read',
            {'resourceRef':self.ref, 'input':{}}, self.resource)
        self.assertEqual(strict_loads(base64.b64decode(result['data'])), self.original)
        self.assertEqual(contract, 'capability-content-reply')
        with self.assertRaisesRegex(ContractError, '^capability_resource_stale$'):
            await self.receiver._read('capability-storage-read',
                {'resourceRef':{**self.ref,'revision':2}, 'input':{}}, self.resource)
        self.assertEqual(len(self.js.messages), 1)

    async def test_outcome_after_lost_ack_preserves_original_identity(self):
        second = record('second',2,1)
        second['authorizationDecision'] = {**self.original['authorizationDecision'], 'operationId':'second'}
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError,'^owner_commit_uncertain$'):
            await self.resource.ledger.append(second,expected_sequence=1)
        query = {'contractId':'capability-storage-write','operationId':'second',
                 'payloadDigest':second['operation']['payloadDigest']}
        # The original resource revision remains 1 even though the aggregate advanced.
        reply, _ = await self.receiver._read('capability-outcome-query',
            {'resourceRef':self.ref,'input':query},self.resource)
        self.assertEqual(reply['recordRef']['id'], second['recordId'])
        self.assertEqual(reply['outcome'],'committed')
        self.assertEqual(len(self.js.messages),2)
        query['payloadDigest']=payload_digest({'changed':True})
        with self.assertRaisesRegex(ContractError,'^capability_outcome_conflict$'):
            await self.receiver._read('capability-outcome-query',
                {'resourceRef':self.ref,'input':query},self.resource)

    async def test_outcome_requires_retained_contract_and_operation_provenance(self):
        for version, variant in enumerate(('missing','contract','operation','actor'), 2):
            operation_id='provenance-'+variant
            value=record(operation_id, version, version-1)
            if variant != 'missing':
                value['authorizationDecision']={**self.original['authorizationDecision'],
                    'operationId':operation_id}
                if variant=='contract':
                    value['authorizationDecision']['contractId']='capability-process-start'
                elif variant=='operation':
                    value['authorizationDecision']['operationId']='other-operation'
                else:
                    value['authorizationDecision']['actorRef']={'id':'other','ownerHubId':'hub-one','revision':1}
            await self.resource.ledger.append(value,expected_sequence=version-1)
            query={'resourceRef':self.ref, 'input':{'contractId':'capability-storage-write',
                'operationId':operation_id,'payloadDigest':value['operation']['payloadDigest']}}
            with self.subTest(variant=variant), self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await self.receiver._read('capability-outcome-query',query,self.resource)
        self.assertEqual(len(self.js.messages),5)

    async def test_real_authority_refuses_missing_capability_grant(self):
        env=self.envelope
        env['contractId']='capability-storage-read'
        env['destinationServiceId']='storage-owner'
        env['payload']={'resourceRef':self.ref,'input':{}}
        env['operation']['payloadDigest']=payload_digest(env['payload'])
        claims=env['ingressAttestation']['claims']
        claims['contractId']=env['contractId']
        claims['audience']['serviceId']='storage-owner'
        claims['operation']=copy.deepcopy(env['operation'])
        env['ingressAttestation']['signature']=sign_claims(claims,SEED)
        with patch('identity.authority._utc_now',return_value=NOW):
            with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await self.receiver.handle(canonical_bytes(env))
        self.assertEqual(len(self.js.messages),1)

    async def test_artifact_reads_retained_metadata_and_checks_digest(self):
        store=Store()
        artifacts=OwnerArtifacts(store,JS(store),bucket='bucket',owner_hub_id='hub-one',
            store_ref={'id':'store','ownerHubId':'hub-one','revision':1},max_bytes=50000)
        artifact=await artifacts.upload(b'original',media_type='text/plain')
        second=record('artifact',2,1)
        second['artifacts']=[artifact]
        await self.resource.ledger.append(second,expected_sequence=1)
        resource=RetainedResource(BINDING,self.resource.ledger,artifacts)
        query={'resourceRef':{**self.ref,'revision':2},'input':{'digest':artifact['digest']}}
        result,_=await self.receiver._read('capability-artifact-read',query,resource)
        self.assertEqual(base64.b64decode(result['data']),b'original')
        store.data=b'changed!'
        with self.assertRaisesRegex(ContractError,'^owner_artifact_corrupt$'):
            await self.receiver._read('capability-artifact-read',query,resource)
        query['input']['digest']=payload_digest({'unretained':True})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.receiver._read('capability-artifact-read',query,resource)

    async def test_oversized_artifact_refused_before_retrieval(self):
        store=Store()
        artifacts=OwnerArtifacts(store,JS(store),bucket='bucket',owner_hub_id='hub-one',
            store_ref={'id':'store','ownerHubId':'hub-one','revision':1},max_bytes=50000)
        artifact=await artifacts.upload(b'x'*45001,media_type='text/plain')
        second=record('large',2,1); second['artifacts']=[artifact]
        await self.resource.ledger.append(second,expected_sequence=1)
        resource=RetainedResource(BINDING,self.resource.ledger,artifacts)
        with patch.object(artifacts,'retrieve',side_effect=AssertionError('must not fetch')):
            with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.receiver._read('capability-artifact-read',
                    {'resourceRef':{**self.ref,'revision':2},'input':{'digest':artifact['digest']}},resource)

    async def test_closure_and_private_repr(self):
        self.assertNotIn('task-one',repr(self.resource)+repr(self.receiver))
        await self.receiver.close()
        with self.assertRaisesRegex(ContractError,'^capability_owner_closed$'):
            await self.receiver.handle(b'{}')
