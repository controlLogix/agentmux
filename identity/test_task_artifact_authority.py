"""Backup artifact bytes require explicit current service authority."""
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity import test_service as support
from identity.test_authority import ref, SEED

CONTRACT = 'task-artifact-backup-read'


class TaskArtifactAuthorityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.ServiceTests.setUp(self)
        state = self.record['state']
        state['transports'][0]['identityRef'] = ref('service')
        grant = state['grants'][0]
        grant.update(contractId=CONTRACT,resourceId='task-one',callerRef=ref('service'),actorRef=ref('service'))
        state['memberships'][0]['identityRef'] = ref('service')
        self.claims.update(contractId=CONTRACT,expectedVersion=1,payload={
            'taskId':'task-one','sourceRevision':1,'artifactRef':{
                'artifactId':'artifact-one','ownerHubId':'hub-one','storeRef':ref('task-artifacts'),
                'version':'version-one','digest':'sha256:'+'a'*64,'bytes':3,'mediaType':'text/plain'}})

    async def admit(self):
        self.js.messages[0].data = canonical_bytes(self.record)
        raw = canonical_bytes({'schemaVersion':'1.0.0','claims':self.claims,
            'signature':sign_claims(self.claims,bytes(reversed(SEED)))})
        return await self.service.ingress.admit(raw,cancellation_ref=ref('backup-cancel'))

    async def test_explicit_service_grant_binds_exact_payload_and_prefix(self):
        result = await self.admit()
        self.assertEqual(result.decision.outcome,'allowed')
        envelope = strict_loads(result.envelope)
        self.assertEqual(envelope['destinationServiceId'],'task-owner')
        self.assertEqual(envelope['payload'],self.claims['payload'])
        self.assertEqual(envelope['operation']['taskId'],'task-one')
        self.assertEqual(envelope['operation']['expectedVersion'],1)
        for field in ('runId','attemptId','delegationRef'):
            self.assertIsNone(envelope['operation'][field])

    async def test_inspect_or_other_task_grants_never_authorize_bytes(self):
        original = copy.deepcopy(self.record)
        for change in ({'contractId':'task-inspect'}, {'contractId':'task-reserve'},
                       {'resourceId':'other-task'}, {'decision':'denied'}):
            self.record = copy.deepcopy(original)
            self.record['state']['grants'][0].update(change)
            result = await self.admit()
            self.assertIsNone(result.envelope)
            self.assertNotEqual(result.decision.outcome,'allowed')

    async def test_nonservice_wrong_prefix_and_foreign_artifact_refuse(self):
        original = copy.deepcopy(self.record)
        for kind in ('human','plugin'):
            self.record = copy.deepcopy(original)
            next(i for i in self.record['state']['identities'] if i['ref']==ref('service'))['kind'] = kind
            result = await self.admit()
            self.assertIsNone(result.envelope)
        self.record = original
        self.claims['expectedVersion'] = 2
        self.assertEqual((await self.admit()).decision.reason,'task_artifact_backup_binding_mismatch')
        self.claims['expectedVersion'] = 1
        self.claims['payload']['artifactRef']['ownerHubId'] = 'other-hub'
        self.assertEqual((await self.admit()).decision.reason,'task_artifact_backup_binding_mismatch')

    async def test_common_exact_approvals_and_revocation_remain_required(self):
        state = self.record['state']
        grant = state['grants'][0]
        grant['decision'] = 'review-required'
        self.assertEqual((await self.admit()).decision.outcome,'review-required')
        approver = copy.deepcopy(grant)
        approver.update(ref=ref('approve-grant'),contractId='identity-approve',resourceId=grant['ref']['id'],decision='allowed')
        state['grants'].append(approver)
        state['approvals'] = [{'ref':ref('backup-approval'),'grantRef':grant['ref'],
            'approverRef':ref('service'),'approverGrantRef':ref('approve-grant'),
            'payloadDigest':payload_digest(self.claims['payload']),
            'audience':{'hubId':'hub-one','serviceId':'task-owner'},'operationId':self.claims['operationId'],
            'expectedVersion':1,'decision':'approved','status':'active',
            'issuedAt':self.claims['issuedAt'],'expiresAt':self.claims['expiresAt']}]
        self.claims['approvalRefs'] = [ref('backup-approval')]
        self.assertEqual((await self.admit()).decision.outcome,'allowed')
        state['approvals'][0]['expectedVersion'] = 2
        self.assertEqual((await self.admit()).decision.reason,'approval_binding_mismatch')
        state['approvals'][0]['expectedVersion'] = 1
        grant['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError,'^credential_grant_unavailable$'):
            await self.admit()
