"""Current actor and original-grant checks for the retained code route."""
import copy
import unittest

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims
from identity.authority import AuthoritySnapshot, evaluate_snapshot
from identity import test_authority as support


class CodeAuthorityTests(unittest.TestCase):
    def request(self, action, kind='human'):
        self.record, self.envelope = support.fixture()
        state = self.record['state']
        state['identities'][0]['kind'] = kind
        contract = 'federation-code-' + action
        payload = {'resourceRef': support.ref('code-one'), 'input': {}}
        if action in ('publish', 'index', 'approve'):
            payload['input'] = {'envelope': {}}
            payload['attribution'] = 'operator'
            if action != 'publish':
                payload['input'].update(subject='am.code.alice.r' + 'a' * 12, localNode='mac')
            if action == 'approve':
                payload['input'].update(quarantineId='held-one', privileged=False)
        elif action == 'fetched':
            payload.update(input={'id': 'share-one'}, attribution='operator')
        elif action == 'outcome':
            payload['input'] = {'contractId': 'federation-code-publish',
                'operationId': 'publish-original', 'payloadDigest': 'sha256:' + 'a' * 64}
        self.envelope.update(contractId=contract, destinationServiceId='storage-owner', payload=payload)
        self.envelope['operation']['caller']['kind'] = kind
        state['grants'][0].update(contractId=contract, resourceId='code-one')
        self.sign()

    def sign(self):
        envelope = self.envelope
        envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
        claims = envelope['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(envelope['operation']), contractId=envelope['contractId'])
        claims['audience']['serviceId'] = 'storage-owner'
        envelope['ingressAttestation']['signature'] = sign_claims(claims, support.SEED)

    def decision(self):
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
            canonical_bytes(self.envelope), audience={'hubId': 'hub-one', 'serviceId': 'storage-owner'},
            now=support.NOW)

    def test_publish_and_fetched_require_human_or_device(self):
        for action in ('publish', 'fetched'):
            for kind in ('human', 'device', 'service', 'plugin'):
                with self.subTest(action=action, kind=kind):
                    self.request(action, kind)
                    self.assertEqual(self.decision().outcome,
                        'allowed' if kind in ('human', 'device') else 'denied')

    def test_index_requires_service_and_native_plugins_use_capability_admission(self):
        for kind in ('human', 'device', 'service', 'plugin'):
            with self.subTest(kind=kind):
                self.request('index', kind)
                self.assertEqual(self.decision().outcome, 'allowed' if kind == 'service' else 'denied')

    def test_approval_requires_human_even_with_an_exact_grant(self):
        for kind in ('human', 'device', 'service', 'plugin'):
            with self.subTest(kind=kind):
                self.request('approve', kind)
                self.assertEqual(self.decision().outcome, 'allowed' if kind == 'human' else 'denied')

    def test_current_scope_resource_revision_and_grant_are_required(self):
        self.request('inspect')
        self.assertEqual(self.decision().outcome, 'allowed')
        self.envelope['payload']['resourceRef']['revision'] = 2
        self.sign()
        self.assertEqual(self.decision().reason, 'code_scope_or_actor_mismatch')
        self.request('inspect')
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.assertEqual(self.decision().outcome, 'denied')
        self.request('inspect')
        self.envelope['payload']['resourceRef']['ownerHubId'] = 'other-hub'
        self.sign()
        self.assertEqual(self.decision().reason, 'code_scope_or_actor_mismatch')
        self.request('inspect')
        self.envelope['operation']['scope']['projectId'] = 'other-project'
        self.sign()
        self.assertEqual(self.decision().reason, 'membership_unavailable')

    def test_outcome_requires_current_original_permission_and_hard_denial_wins(self):
        self.request('outcome')
        self.assertEqual(self.decision().reason, 'code_original_authority_unavailable')
        original = copy.deepcopy(self.record['state']['grants'][0])
        original.update(ref=support.ref('publish-grant'), contractId='federation-code-publish')
        self.record['state']['grants'].append(original)
        self.assertEqual(self.decision().outcome, 'allowed')
        denied = copy.deepcopy(original)
        denied.update(ref=support.ref('publish-denied'), decision='denied')
        self.record['state']['grants'].append(denied)
        self.assertEqual(self.decision().reason, 'code_original_authority_unavailable')


if __name__ == '__main__':
    unittest.main()
