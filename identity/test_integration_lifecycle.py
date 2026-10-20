"""Current authority for lifecycle commands; no provider dispatch is performed."""
import copy
import unittest

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims
from identity.authority import AuthoritySnapshot, evaluate_snapshot
from identity.test_authority import fixture, ref, NOW, SEED


class IntegrationLifecycleTests(unittest.TestCase):
    def setup_command(self, contract):
        self.record, self.envelope = fixture()
        self.envelope.update(contractId=contract, destinationServiceId='integration-owner',
            payload={'effectRef': ref('effect-one'), 'originalOperationId': 'original-one',
                'originalPayloadDigest': 'sha256:' + 'a' * 64,
                'attemptOperationId': 'operation-one' if contract == 'integration-attempt-start' else 'attempt-one'})
        self.record['state']['grants'][0].update(contractId=contract, resourceId='effect-one')
        original = copy.deepcopy(self.record['state']['grants'][0])
        original.update(ref=ref('original-grant'), contractId='integration-intent')
        self.record['state']['grants'].append(original)

    def check(self):
        self.envelope['operation']['payloadDigest'] = payload_digest(self.envelope['payload'])
        claims = self.envelope['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(self.envelope['operation']), contractId=self.envelope['contractId'],
                      audience={'hubId': 'hub-one', 'serviceId': 'integration-owner'})
        self.envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
            canonical_bytes(self.envelope), audience=claims['audience'], now=NOW)

    def test_start_needs_fresh_approval_bound_to_attempt(self):
        self.setup_command('integration-attempt-start')
        self.assertEqual(self.check().outcome, 'review-required')
        operation = self.envelope['operation']
        approver = copy.deepcopy(self.record['state']['grants'][0])
        approver.update(ref=ref('approver'), contractId='identity-approve', resourceId='grant')
        self.record['state']['grants'].append(approver)
        self.record['state']['approvals'] = [{'ref': ref('approval'), 'grantRef': ref('grant'),
            'approverRef': ref('human'), 'approverGrantRef': ref('approver'), 'decision': 'approved',
            'status': 'active', 'issuedAt': approver['issuedAt'], 'expiresAt': approver['expiresAt'],
            'payloadDigest': operation['payloadDigest'], 'operationId': operation['operationId'],
            'expectedVersion': operation['expectedVersion'],
            'audience': {'hubId': 'hub-one', 'serviceId': 'integration-owner'}}]
        operation['approvalRefs'] = [ref('approval')]
        self.assertEqual(self.check().outcome, 'allowed')
        self.record['state']['approvals'][0]['operationId'] = 'original-one'
        self.assertEqual(self.check().reason, 'approval_binding_mismatch')

    def test_completion_and_reconcile_need_original_authority_and_distinct_identity(self):
        for contract in ('integration-attempt-complete', 'integration-effect-reconcile'):
            with self.subTest(contract=contract):
                self.setup_command(contract)
                self.assertEqual(self.check().outcome, 'allowed')
                self.envelope['payload']['attemptOperationId'] = self.envelope['operation']['operationId']
                self.assertEqual(self.check().reason, 'integration_operation_binding')
                self.envelope['payload']['attemptOperationId'] = 'attempt-one'
                self.record['state']['grants'][1]['decision'] = 'denied'
                self.assertEqual(self.check().reason, 'integration_original_authority_unavailable')
