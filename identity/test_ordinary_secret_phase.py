"""Current service authority for retained secret dispatch and completion."""
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, validate
from identity.authority import AuthoritySnapshot, evaluate_snapshot
from identity import test_ordinary_secret as support


class OrdinarySecretPhaseTests(unittest.TestCase):
    def request(self, action='dispatch', *, actor='custody'):
        self.record, outer, template = support.resolution_fixture()
        contract = 'ordinary-secret-' + action
        payload = {'resourceRef': support.ref('ordinary-one'),
            'journalRef': support.ref('use-journal'), 'claimRef': support.ref('prepared-one'),
            'originalOperationId': outer['payload']['originalEnvelope']['operation']['operationId'],
            'originalPayloadDigest': outer['payload']['originalEnvelope']['operation']['payloadDigest'],
            'enrollmentDigest': 'sha256:' + 'a' * 64}
        if action == 'complete':
            payload['observationId'] = 'observation-one'
        state = self.record['state']
        grant = copy.deepcopy(state['grants'][-1])
        grant.update(ref=support.ref('phase-grant'), contractId=contract,
            callerRef=support.ref(actor), actorRef=support.ref(actor))
        state['grants'].append(grant)
        if actor == 'consumer':
            transport = copy.deepcopy(state['transports'][-1])
            transport.update(ref=support.ref('consumer-transport'), identityRef=support.ref(actor))
            state['transports'].append(transport)
        self.envelope = support.signed_envelope(template, contract=contract, payload=payload,
            actor=actor, grant='phase-grant', scope=support.SCOPE, version=1)
        self.envelope['destinationServiceId'] = 'secret-owner'
        self.sign()

    def sign(self):
        self.envelope['operation']['payloadDigest'] = payload_digest(self.envelope['payload'])
        claims = self.envelope['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(self.envelope['operation']),
            audience={'hubId': 'hub-one', 'serviceId': 'secret-owner'})
        self.envelope['ingressAttestation']['signature'] = sign_claims(claims, support.SEED)

    def decision(self):
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
            canonical_bytes(self.envelope),
            audience={'hubId': 'hub-one', 'serviceId': 'secret-owner'}, now=support.NOW)

    def test_only_current_enrolled_custody_service_may_run_phases(self):
        for action in ('dispatch', 'complete'):
            self.request(action)
            self.assertEqual(self.decision().outcome, 'allowed')
            for kind in ('human', 'device', 'plugin'):
                self.request(action)
                next(row for row in self.record['state']['identities']
                    if row['ref'] == support.ref('custody'))['kind'] = kind
                self.envelope['operation']['caller']['kind'] = kind
                self.sign()
                with self.subTest(action=action, kind=kind):
                    self.assertEqual(self.decision().outcome, 'denied')
            self.request(action, actor='consumer')
            self.assertEqual(self.decision().reason, 'ordinary_secret_phase_binding_mismatch')

    def test_journal_claim_generation_original_and_scope_are_bound(self):
        mutations = [lambda p: p['journalRef'].update(revision=2),
            lambda p: p['journalRef'].update(ownerHubId='other-hub'),
            lambda p: p['claimRef'].update(ownerHubId='other-hub'),
            lambda p: p['resourceRef'].update(id='different-secret'),
            lambda p: p['resourceRef'].update(ownerHubId='other-hub'),
            lambda p: p.update(originalOperationId=self.envelope['operation']['operationId'])]
        for action in ('dispatch', 'complete'):
            for mutate in mutations:
                self.request(action)
                mutate(self.envelope['payload'])
                self.sign()
                with self.subTest(action=action, change=mutate):
                    self.assertEqual(self.decision().outcome, 'denied')
            self.request(action)
            self.record['state']['ordinarySecretReferences'][0]['scope']['projectId'] = 'other-project'
            self.assertEqual(self.decision().outcome, 'denied')

    def test_current_phase_grant_transport_identity_and_membership_are_required(self):
        for action in ('dispatch', 'complete'):
            for collection, name in (('grants', 'phase-grant'), ('transports', 'custody-transport'),
                    ('identities', 'custody'), ('memberships', 'custody-member')):
                self.request(action)
                next(row for row in self.record['state'][collection]
                    if row['ref']['id'] == name)['status'] = 'revoked'
                with self.subTest(action=action, collection=collection):
                    self.assertEqual(self.decision().outcome, 'denied')
            self.request(action)
            denied = copy.deepcopy(self.record['state']['grants'][-1])
            denied.update(ref=support.ref('phase-denied'), decision='denied')
            self.record['state']['grants'].append(denied)
            self.assertEqual(self.decision().reason, 'hard_denial')

    def test_completion_retains_physical_result_after_original_revocation(self):
        for action in ('dispatch', 'complete'):
            for collection, name in (('identities', 'human'), ('identities', 'consumer'),
                    ('ordinarySecretReferences', 'ordinary-one')):
                self.request(action)
                next(row for row in self.record['state'][collection]
                    if row['ref']['id'] == name)['status'] = 'revoked'
                with self.subTest(action=action, collection=collection):
                    self.assertEqual(self.decision().outcome,
                        'allowed' if action == 'complete' else 'denied')
        self.request('complete')
        generation = self.record['state']['ordinarySecretReferences'][0]
        generation.update(status='revoked', ref={**support.ref('ordinary-one'), 'revision': 2},
            expiresAt='2026-10-09T12:00:01Z')
        self.assertEqual(self.decision().outcome, 'allowed')

    def test_dispatch_deadline_cannot_outlive_generation(self):
        self.request()
        self.record['state']['ordinarySecretReferences'][0]['expiresAt'] = '2026-10-09T12:00:31Z'
        self.assertEqual(self.decision().valid_until.isoformat(), '2026-10-09T12:00:31+00:00')

    def test_workspace_scope_may_only_narrow_enrollment(self):
        for action in ('dispatch', 'complete'):
            self.request(action)
            scope = {**support.SCOPE, 'workspaceId': 'workspace-one'}
            self.envelope['operation']['scope'] = scope
            self.record['state']['grants'][-1]['scope'] = scope
            self.record['state']['memberships'].append({'ref': support.ref('phase-child-member'),
                'identityRef': support.ref('custody'), 'scope': scope, 'status': 'active'})
            self.sign()
            self.assertEqual(self.decision().outcome, 'allowed')
            self.record['state']['ordinarySecretReferences'][0]['scope']['workspaceId'] = 'other-workspace'
            self.assertEqual(self.decision().outcome, 'denied')

    def test_closed_phase_schema_cannot_carry_outcome_or_private_material(self):
        for action in ('dispatch', 'complete'):
            self.request(action)
            contract, payload = self.envelope['contractId'], self.envelope['payload']
            validate(contract, payload)
            for field in ('outcome', 'secretBytes', 'body', 'account', 'path', 'callback'):
                with self.subTest(action=action, field=field), self.assertRaises(ContractError):
                    validate(contract, {**payload, field: 'forbidden'})
            for key in ('journalRef', 'claimRef', 'resourceRef'):
                changed = copy.deepcopy(payload)
                changed[key]['revision'] = 0
                with self.subTest(action=action, ref=key), self.assertRaises(ContractError):
                    validate(contract, changed)


if __name__ == '__main__':
    unittest.main()
