"""Conversation artifact references require current, exact archive authority."""
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity import test_service as authority_support
from identity.test_authority import ref, SEED
from identity.test_authority import NOW
from identity.authority import AuthoritySnapshot, evaluate_snapshot


class ConversationImportIngressTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        authority_support.ServiceTests.setUp(self)
        payload = {'archiveId':'archive-one','sourceRef':ref('legacy-source'),
            'captureDigest':'sha256:'+'a'*64,'bundleDigest':'sha256:'+'b'*64,
            'artifactRef':{'artifactId':'encrypted-conversations','ownerHubId':'hub-one',
                'storeRef':ref('archive-store'),'version':'version-one','digest':'sha256:'+'c'*64,
                'bytes':100,'mediaType':'application/octet-stream'}}
        self.record['state']['grants'][0].update(contractId='conversation-ledger-import',resourceId='archive-one')
        self.claims.update(contractId='conversation-ledger-import',payload=payload,
            operationId='conversation-import-one',expectedVersion=0)

    async def admit(self, *, context=None):
        self.js.messages[0].data = canonical_bytes(self.record)
        request = canonical_bytes({'schemaVersion':'1.0.0','claims':self.claims,
            'signature':sign_claims(self.claims,bytes(reversed(SEED)))})
        return await self.service.ingress.admit(request,cancellation_ref=ref('import-cancel'),reservation_context=context)

    async def test_exact_import_grant_preserves_capture_without_execution_lineage(self):
        result = await self.admit()
        self.assertEqual(result.decision.outcome,'allowed')
        envelope = strict_loads(result.envelope)
        self.assertEqual(envelope['destinationServiceId'],'conversation-ledger-owner')
        self.assertEqual(envelope['payload'],self.claims['payload'])
        operation = envelope['operation']
        self.assertEqual(operation['expectedVersion'],0)
        self.assertEqual(operation['caller']['authenticatedIdentityRef'],operation['effectiveActorRef'])
        for field in ('taskId','runId','attemptId','delegationRef'):
            self.assertIsNone(operation[field])
        self.assertNotEqual(operation['grantRef']['id'],'old-grant')

    async def test_inspect_reserve_other_task_and_legacy_evidence_grant_no_import_authority(self):
        original = copy.deepcopy(self.record)
        for fields in ({'contractId':'task-inspect'}, {'contractId':'task-reserve'}, {'contractId':'task-import'}, {'contractId':'identity-revoke'},
                       {'resourceId':'another-task'}, {'decision':'denied'}):
            self.record = copy.deepcopy(original)
            self.record['state']['grants'][0].update(fields)
            result = await self.admit()
            self.assertNotEqual(result.decision.outcome,'allowed')
            self.assertIsNone(result.envelope)

    async def test_nonzero_target_version_plugin_and_delegated_grant_refuse(self):
        self.claims['expectedVersion'] = 1
        result = await self.admit()
        self.assertEqual(result.decision.reason,'conversation_import_binding_mismatch')
        self.assertIsNone(result.envelope)
        self.claims['expectedVersion'] = 0
        caller = self.record['state']['grants'][0]['callerRef']
        identity = next(i for i in self.record['state']['identities'] if i['ref']==caller)
        identity['kind'] = 'plugin'
        result = await self.admit()
        self.assertEqual(result.decision.reason,'native_capability_admission_required')
        self.assertIsNone(result.envelope)
        identity['kind'] = 'human'
        self.record['state']['grants'][0]['delegationRef'] = ref('delegated')
        with self.assertRaisesRegex(ContractError,'^credential_grant_unavailable$'):
            await self.admit()

    async def test_current_exact_approval_and_hard_denial_follow_common_rules(self):
        state = self.record['state']
        grant = state['grants'][0]
        grant['decision'] = 'review-required'
        self.assertEqual((await self.admit()).decision.outcome,'review-required')
        approval_grant = copy.deepcopy(grant)
        approval_grant.update(ref=ref('approve-grant'),contractId='identity-approve',resourceId=grant['ref']['id'],decision='allowed')
        state['grants'].append(approval_grant)
        state['approvals'] = [{'ref':ref('import-approval'),'grantRef':grant['ref'],
            'approverRef':grant['actorRef'],'approverGrantRef':ref('approve-grant'),
            'payloadDigest':payload_digest(self.claims['payload']),
            'audience':{'hubId':'hub-one','serviceId':'conversation-ledger-owner'},
            'operationId':self.claims['operationId'],'expectedVersion':0,
            'decision':'approved','status':'active','issuedAt':self.claims['issuedAt'],'expiresAt':self.claims['expiresAt']}]
        self.claims['approvalRefs'] = [ref('import-approval')]
        self.assertEqual((await self.admit()).decision.outcome,'allowed')
        state['approvals'][0]['expectedVersion'] = 1
        self.assertEqual((await self.admit()).decision.reason,'approval_binding_mismatch')
        state['approvals'][0]['expectedVersion'] = 0
        hard = copy.deepcopy(grant)
        hard.update(ref=ref('hard-deny'),decision='denied')
        state['grants'].append(hard)
        self.assertEqual((await self.admit()).decision.reason,'hard_denial')

    async def test_replay_rechecks_revocation_and_rejects_reservation_context(self):
        first = await self.admit()
        second = await self.admit()
        self.assertEqual(strict_loads(first.envelope)['operation'],strict_loads(second.envelope)['operation'])
        with self.assertRaisesRegex(ContractError,'^task_reservation_preparation_required$'):
            await self.admit(context={})
        self.record['state']['grants'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError,'^credential_grant_unavailable$'):
            await self.admit()

    async def test_service_caller_uses_same_explicit_archive_grant(self):
        caller = self.record['state']['grants'][0]['callerRef']
        identity = next(i for i in self.record['state']['identities'] if i['ref'] == caller)
        identity['kind'] = 'service'
        self.assertEqual((await self.admit()).decision.outcome, 'allowed')

    async def test_organization_scope_is_exact_and_cannot_be_project_authority(self):
        original = copy.deepcopy(self.record)
        for field in ('projectId', 'workspaceId'):
            self.record = copy.deepcopy(original)
            self.record['state']['grants'][0]['scope'][field] = 'selected-scope'
            self.record['state']['memberships'][0]['scope'][field] = 'selected-scope'
            result = await self.admit()
            self.assertEqual(result.decision.reason, 'conversation_import_binding_mismatch')
            self.assertIsNone(result.envelope)
        self.record = original
        self.claims['payload']['artifactRef']['ownerHubId'] = 'another-hub'
        result = await self.admit()
        self.assertEqual(result.decision.reason, 'conversation_import_binding_mismatch')
        self.assertIsNone(result.envelope)

    async def test_owner_evaluation_refuses_signed_execution_lineage(self):
        original = strict_loads((await self.admit()).envelope)
        for field, value in (('taskId', 'task-one'), ('runId', 'run-one'),
                             ('attemptId', 'attempt-one'), ('delegationRef', ref('delegation'))):
            envelope = copy.deepcopy(original)
            envelope['operation'][field] = value
            claims = envelope['ingressAttestation']['claims']
            claims['operation'] = copy.deepcopy(envelope['operation'])
            envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
            decision = evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 1),
                canonical_bytes(envelope), audience=claims['audience'], now=NOW)
            self.assertEqual(decision.outcome, 'denied')

    async def test_artifact_store_hub_and_other_archive_grants_refuse(self):
        self.claims['payload']['artifactRef']['storeRef']['ownerHubId'] = 'other-hub'
        self.assertEqual((await self.admit()).decision.reason,'conversation_import_binding_mismatch')
        self.claims['payload']['artifactRef']['storeRef']['ownerHubId'] = 'hub-one'
        self.record['state']['grants'][0]['resourceId'] = 'other-archive'
        self.assertNotEqual((await self.admit()).decision.outcome,'allowed')
