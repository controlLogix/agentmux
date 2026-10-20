"""Offline enrolled admission and receiving checks with actual retained ledgers."""
import base64
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from capability_owner.receiver import CapabilityReceiver, _DESTINATIONS
from capability_owner.resources import RetainedResource
from identity.capability_routes import CAPABILITY_DESTINATIONS
from identity import test_service
from identity.test_authority import ref, SEED, NOW
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.test_ledger import FakeJetStream, CREATED, record


class CapabilityAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        test_service.ServiceTests.setUp(self)
        patch('identity.authority._utc_now', return_value=NOW).start()
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('capability'), contractId='capability-storage-read', resourceId='task-one')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.resource_js = FakeJetStream(self.policy)
        scope = self.record['state']['grants'][0]['scope']
        binding = OwnerBinding('hub-one', 'task', 'task-one', 'task', canonical_bytes(scope))
        self.resource = RetainedResource.open_existing(self.resource_js, binding=binding, stream='OWNER',
            stream_identity=StreamIdentity(CREATED, 0), retention=self.policy)
        self.resource_js.config = self.policy.stream_config(stream='OWNER', subject=self.resource.ledger._subject)
        self.original = record(); self.original['operation']['scope'] = copy.deepcopy(scope)
        self.original['authorizationDecision'] = {
            'operationId': self.original['operation']['operationId'], 'decision': 'allowed',
            'reason': 'current_authority', 'actorRef': self.original['operation']['effectiveActorRef'],
            'contractId': 'capability-storage-write'}
        self.receiver = CapabilityReceiver(self.service.reader, hub_id='hub-one', resources=[self.resource])
        self.addAsyncCleanup(self.receiver.close)
        self.claims.update(operationId='read-operation', grantRef=ref('capability'),
            contractId='capability-storage-read', payload={'resourceRef': ref('task-one'), 'input': {}})

    request = test_service.ServiceTests.request

    async def asyncSetUp(self):
        await self.resource.ledger.append(self.original, expected_sequence=0)

    async def admit(self):
        return await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))

    async def test_read_through_enrolled_ingress_and_two_retained_ledgers(self):
        admitted = await self.admit()
        self.assertEqual(admitted.decision.outcome, 'allowed')
        reply = await self.receiver.handle(admitted.envelope)
        self.assertEqual(reply.contract_id, 'capability-content-reply')
        self.assertEqual(strict_loads(base64.b64decode(strict_loads(reply.payload)['data'])), self.original)
        self.assertEqual(len(self.resource_js.messages), 1)

    async def test_wrong_resource_hub_is_denied_at_admission(self):
        self.claims['payload']['resourceRef']['ownerHubId'] = 'other-hub'
        result = await self.admit()
        self.assertEqual((result.decision.outcome, result.decision.reason), ('denied', 'capability_owner_mismatch'))
        self.assertIsNone(result.envelope)

    async def test_scope_mismatch_cannot_disclose_resource(self):
        scope = {'organizationId': 'org-one', 'projectId': 'other-project', 'workspaceId': None}
        self.record['state']['memberships'][0]['scope'] = scope
        self.record['state']['grants'][1]['scope'] = copy.deepcopy(scope)
        self.js.messages[0].data = canonical_bytes(self.record)
        admitted = await self.admit()
        self.assertEqual(admitted.decision.outcome, 'allowed')
        with self.assertRaisesRegex(ContractError, 'capability_access_refused'):
            await self.receiver.handle(admitted.envelope)

    async def test_grant_revocation_during_read_prevents_disclosure(self):
        admitted = await self.admit()
        original = self.resource_js.stream_info
        revoked = False
        async def revoke(*args, **kwargs):
            nonlocal revoked
            if not revoked:
                revoked = True
                self.claims.update(operationId='revoke-capability', contractId='identity-revoke',
                    grantRef=ref('grant'), payload={'authorityId': 'authority-one', 'targetRef': ref('capability')})
                receipt = strict_loads(await self.service.handle(self.request()))
                self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
            return await original(*args, **kwargs)
        self.resource_js.stream_info = revoke
        with self.assertRaisesRegex(ContractError, 'capability_access_refused'):
            await self.receiver.handle(admitted.envelope)
        self.assertTrue(revoked)
        self.assertEqual(len(self.js.messages), 2)
        self.assertEqual(len(self.resource_js.messages), 1)

    async def test_outcome_query_requires_original_permission_and_hard_denial_wins(self):
        self.record['state']['grants'][1]['contractId'] = 'capability-outcome-query'
        self.claims.update(contractId='capability-outcome-query', payload={'resourceRef': ref('task-one'),
            'input': {'contractId': 'capability-storage-write', 'operationId': 'operation-one',
                      'payloadDigest': self.original['operation']['payloadDigest']}})
        self.js.messages[0].data = canonical_bytes(self.record)
        denied = await self.admit()
        self.assertEqual(denied.decision.reason, 'capability_original_authority_unavailable')
        grant = copy.deepcopy(self.record['state']['grants'][1])
        grant.update(ref=ref('write'), contractId='capability-storage-write')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        allowed = await self.admit()
        self.assertEqual(allowed.decision.outcome, 'allowed')
        reply = await self.receiver.handle(allowed.envelope)
        self.assertEqual(strict_loads(reply.payload)['outcome'], 'committed')
        deny = copy.deepcopy(grant); deny.update(ref=ref('deny-write'), decision='denied')
        self.record['state']['grants'].append(deny)
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'capability_access_refused'):
            await self.receiver.handle(allowed.envelope)
        self.assertEqual((await self.admit()).decision.reason, 'capability_original_authority_unavailable')

    async def test_wrong_destination_cannot_disclose_resource(self):
        admitted = await self.admit()
        envelope = strict_loads(admitted.envelope)
        envelope['destinationServiceId'] = 'artifact-owner'
        claims = envelope['ingressAttestation']['claims']
        claims['audience']['serviceId'] = 'artifact-owner'
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        with self.assertRaises(ContractError):
            await self.receiver.handle(canonical_bytes(envelope))

    async def test_direct_plugin_credential_cannot_bypass_native_capabilities(self):
        self.record['state']['identities'][0]['kind'] = 'plugin'
        self.js.messages[0].data = canonical_bytes(self.record)
        result = await self.admit()
        self.assertEqual(result.decision.reason, 'native_capability_admission_required')
        self.assertIsNone(result.envelope)

    def test_fixed_routes_match_registry_and_receiver(self):
        registry = json.loads((Path(__file__).resolve().parents[1] / 'contracts/v1/registry.json').read_text())['contracts']
        self.assertEqual(len(CAPABILITY_DESTINATIONS), 10)
        self.assertEqual(CAPABILITY_DESTINATIONS, _DESTINATIONS)
        for contract, destination in CAPABILITY_DESTINATIONS.items():
            self.assertEqual(registry[contract]['destinationServiceId'], destination)
            self.assertEqual(registry[contract]['major'], 1)

    async def test_write_revision_must_match_enrolled_resource_reference(self):
        self.record['state']['grants'][1]['contractId'] = 'capability-storage-write'
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims.update(contractId='capability-storage-write', expectedVersion=2,
            payload={'resourceRef': ref('task-one'), 'input': {'value': {'example': True}}})
        result = await self.admit()
        self.assertEqual(result.decision.reason, 'capability_version_mismatch')
        self.assertIsNone(result.envelope)
