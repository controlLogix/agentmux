"""Offline boundary tests; fixture keys are never enrollment credentials."""
import asyncio
import base64
import copy
from datetime import timedelta
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from sdk.python.tests.test_contracts import example, SEED, NOW
from identity.authority import AuthorityReader, AuthoritySnapshot, evaluate_snapshot


def ref(name):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}


def fixture():
    envelope = example()
    claims = envelope['ingressAttestation']['claims']
    op = claims['operation']
    op['caller']['authenticatedIdentityRef'] = ref('human')
    op['effectiveActorRef'] = ref('human')
    op['grantRef'] = ref('grant')
    claims['signingKeyRef'], claims['authenticatedTransportRef'] = ref('issuer'), ref('transport')
    envelope['operation'] = copy.deepcopy(op)
    envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
    interval = {'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z', 'status': 'active'}
    state = {
        'schemaVersion': '1.0.0', 'profileId': 'profile-one', 'organizationId': 'org-one',
        'identities': [
            {'ref': ref('human'), 'principalId': 'user-one', 'kind': 'human', 'status': 'active', 'externalIdentity': None},
            {'ref': ref('service'), 'principalId': 'ingress', 'kind': 'service', 'status': 'active', 'externalIdentity': None}],
        'issuers': [{'ref': ref('issuer'), 'identityRef': ref('service'), 'instanceId': 'ingress-one',
                     'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='), **interval}],
        'transports': [{'ref': ref('transport'), 'identityRef': ref('human'), 'issuerRef': ref('issuer'),
                        'method': 'nats-credential-mapping',
                        'publicKey': base64.urlsafe_b64encode(bytes(SigningKey(bytes(reversed(SEED))).verify_key)).decode().rstrip('='), **interval}],
        'memberships': [{'ref': ref('member'), 'identityRef': ref('human'), 'scope': copy.deepcopy(op['scope']), 'status': 'active'}],
        'grants': [{'ref': ref('grant'), 'callerRef': ref('human'), 'actorRef': ref('human'),
                    'scope': copy.deepcopy(op['scope']), 'contractId': 'task-inspect', 'resourceId': 'task-one',
                    'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None, **interval}],
        'approvals': []}
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / 'tests/contracts/vectors/valid-examples.json').read_text())['owner-record']
    record.update(entityId='authority-one', entityKind='identity-authority', ownerHubId='hub-one',
                  ownerDomain='identity', operation=copy.deepcopy(op), state=state)
    return record, envelope


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.record, self.env = fixture()
        self.audience = {'hubId': 'hub-one', 'serviceId': 'task-owner'}

    def check(self):
        return evaluate_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
                                 canonical_bytes(self.env), audience=self.audience, now=NOW)

    def resign(self):
        claims = self.env['ingressAttestation']['claims']
        for k in ('operation', 'contractId', 'destinationServiceId'):
            if k == 'destinationServiceId':
                claims['audience']['serviceId'] = self.env[k]
            else:
                claims[k] = copy.deepcopy(self.env[k])
        self.env['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    def test_current_direct_actor_and_private_result(self):
        decision = self.check()
        self.assertEqual((decision.outcome, decision.audit_actor), ('allowed', 'user-one'))
        self.assertNotIn('user-one', repr(decision))
        self.assertEqual(json.loads(decision.authority_ref)['revision'], self.record['entityVersion'])
        self.assertEqual(decision.authority_sequence, 17)
        self.env['operation']['caller']['principalId'] = 'changed'
        self.assertIn(b'user-one', decision.operation)

    def test_revocation_at_each_binding_and_scope(self):
        original = copy.deepcopy(self.record)
        for collection in ('identities', 'issuers', 'transports', 'memberships', 'grants'):
            with self.subTest(collection=collection):
                self.record = copy.deepcopy(original)
                self.record['state'][collection][0]['status'] = 'revoked'
                self.assertEqual(self.check().outcome, 'denied')
        self.record = original
        self.env['operation']['scope']['projectId'] = 'other-project'
        self.resign()
        self.assertEqual(self.check().reason, 'membership_unavailable')

    def test_valid_signature_does_not_permit_actor_or_transport_substitution(self):
        self.env['operation']['caller']['principalId'] = 'admin'
        self.resign()
        self.assertEqual(self.check().reason, 'identity_binding_mismatch')
        self.record, self.env = fixture()
        self.record['state']['transports'][0]['issuerRef'] = ref('other-issuer')
        self.assertEqual(self.check().reason, 'identity_binding_mismatch')

    def test_current_revision_and_expiry_are_required(self):
        self.record['state']['grants'][0]['ref']['revision'] = 2
        self.assertEqual(self.check().reason, 'grant_unavailable')
        self.record, self.env = fixture()
        self.record['state']['issuers'][0]['expiresAt'] = NOW.isoformat().replace('+00:00', 'Z')
        self.assertEqual(self.check().reason, 'issuer_unavailable')

    def test_approval_and_hard_denial(self):
        state = self.record['state']
        state['grants'][0]['decision'] = 'review-required'
        self.assertEqual(self.check().outcome, 'review-required')
        state['approvals'] = [{'ref': ref('approval'), 'grantRef': ref('grant'), 'approverRef': ref('human'),
            'payloadDigest': self.env['operation']['payloadDigest'], 'audience': self.audience.copy(),
            'operationId': self.env['operation']['operationId'], 'expectedVersion': 1, 'approverGrantRef': ref('approve-grant'),
            'decision': 'approved', 'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:10:00Z'}]
        approval_grant = copy.deepcopy(state['grants'][0])
        approval_grant.update(ref=ref('approve-grant'), contractId='identity-approve', resourceId='grant', decision='allowed')
        state['grants'].append(approval_grant)
        self.env['operation']['approvalRefs'] = [ref('approval')]
        self.resign()
        self.assertEqual(self.check().outcome, 'allowed')
        hard = copy.deepcopy(state['grants'][0]); hard.update(ref=ref('hard-deny'), decision='denied')
        state['grants'].append(hard)
        self.assertEqual(self.check().reason, 'hard_denial')
        state['grants'].pop()
        state['approvals'][0]['payloadDigest'] = 'sha256:' + '0' * 64
        self.assertEqual(self.check().reason, 'approval_binding_mismatch')

    def test_integration_intent_requires_approval_even_for_allowed_grant(self):
        self.env.update(contractId='integration-intent', destinationServiceId='integration-owner')
        self.env['payload'] = {'effectRef': ref('effect-one'), 'credentialRef': ref('credential-one'),
            'action': 'jira-transition', 'target': {'issueKey': 'AMUX-66', 'transitionId': '31'}, 'contentRef': None}
        self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
        self.audience['serviceId'] = 'integration-owner'
        state = self.record['state']
        state['grants'][0].update(contractId='integration-intent', resourceId='effect-one')
        self.resign()
        self.assertEqual(self.check().outcome, 'review-required')
        approval_grant = copy.deepcopy(state['grants'][0])
        approval_grant.update(ref=ref('approve-grant'), contractId='identity-approve', resourceId='grant')
        state['grants'].append(approval_grant)
        state['approvals'] = [{'ref': ref('approval'), 'grantRef': ref('grant'), 'approverRef': ref('human'),
            'payloadDigest': self.env['operation']['payloadDigest'], 'audience': self.audience.copy(),
            'operationId': self.env['operation']['operationId'], 'expectedVersion': 1,
            'approverGrantRef': ref('approve-grant'), 'decision': 'approved', 'status': 'active',
            'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z'}]
        self.env['operation']['approvalRefs'] = [ref('approval')]
        self.resign()
        self.assertEqual(self.check().outcome, 'allowed')
        self.env['payload']['effectRef']['revision'] = 2
        self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
        self.resign()
        self.assertEqual(self.check().reason, 'integration_scope_or_version_mismatch')

    def test_signed_payload_tampering_and_unenrolled_key(self):
        self.env['payload']['taskId'] = 'other-task'
        with self.assertRaises(ContractError): self.check()
        self.record, self.env = fixture()
        self.env['ingressAttestation']['claims']['signingKeyRef'] = ref('unknown')
        self.assertEqual(self.check().reason, 'issuer_unavailable')

    def test_ambiguous_records_and_delegation_fail_closed(self):
        self.record['state']['identities'].append(copy.deepcopy(self.record['state']['identities'][0]))
        with self.assertRaisesRegex(ContractError, 'authority_reference_ambiguous'): self.check()
        self.record, self.env = fixture()
        self.env['operation']['delegationRef'] = ref('delegation')
        self.resign()
        self.assertEqual(self.check().reason, 'delegation_not_supported')

    def test_global_definition_requires_explicit_global_scope(self):
        self.env.update(contractId='definition-save', destinationServiceId='definition-owner')
        self.env['payload'] = {'definitionId': 'definition-one', 'scope': 'global', 'name': 'worker',
                               'expectedChecksum': 'sha256:' + 'a' * 64, 'definition': {'description': 'Review changes.', 'persona': 'Review changes.'}}
        self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
        self.audience['serviceId'] = 'definition-owner'
        self.resign()
        self.record['state']['grants'][0].update(contractId='definition-save', resourceId='definition-one', definitionTarget={'scope': 'global', 'name': 'worker'})
        self.assertEqual(self.check().reason, 'definition_scope_mismatch')
        self.env['operation']['scope'].update(projectId=None, workspaceId=None)
        for collection in ('memberships', 'grants'):
            self.record['state'][collection][0]['scope'] = copy.deepcopy(self.env['operation']['scope'])
        self.resign()
        self.assertEqual(self.check().outcome, 'allowed')


    def test_effect_commands_require_their_own_exact_target_grant(self):
        for contract in ('definition-effect-query', 'definition-effect-complete', 'definition-effect-retry'):
            self.env.update(contractId=contract, destinationServiceId='definition-owner')
            self.env['payload'] = {'definitionId': 'definition-one', 'scope': 'repo', 'name': 'worker',
                'originalOperationId': 'save-one', 'originalPayloadDigest': 'sha256:' + 'a' * 64,
                'effectId': 'effect-one'}
            if contract != 'definition-effect-query':
                self.env['payload']['attemptOperationId'] = 'attempt-one'
            self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
            self.audience['serviceId'] = 'definition-owner'
            grant = self.record['state']['grants'][0]
            grant.update(contractId=contract, resourceId='definition-one',
                         definitionTarget={'name': 'worker', 'scope': 'repo'})
            self.resign()
            self.assertEqual(self.check().outcome, 'allowed')
            grant['definitionTarget']['name'] = 'other-worker'
            self.assertEqual(self.check().reason, 'grant_unavailable')

    def test_definition_name_substitution_is_denied(self):
        self.env.update(contractId='definition-save', destinationServiceId='definition-owner')
        self.env['payload'] = {'definitionId': 'definition-one', 'scope': 'repo', 'name': 'other-worker',
            'expectedChecksum': 'sha256:' + 'a' * 64, 'definition': {'description': 'Review'}}
        self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
        self.audience['serviceId'] = 'definition-owner'
        self.record['state']['grants'][0].update(contractId='definition-save', resourceId='definition-one',
                                               definitionTarget={'name': 'worker', 'scope': 'repo'})
        self.resign()
        self.assertEqual(self.check().reason, 'grant_unavailable')

    def test_approval_operation_and_version_are_bound(self):
        # Reuse the fully bound approval setup and then remove its tampering.
        self.test_approval_and_hard_denial()
        approval = self.record['state']['approvals'][0]
        approval['payloadDigest'] = self.env['operation']['payloadDigest']
        for field, value in [('operationId', 'different-operation'), ('expectedVersion', 2)]:
            prior = self.env['operation'][field]
            self.env['operation'][field] = value
            self.resign()
            self.assertEqual(self.check().reason, 'approval_binding_mismatch')
            self.env['operation'][field] = prior
        self.resign()
        self.record['state']['grants'][1]['status'] = 'revoked'
        self.assertEqual(self.check().reason, 'approval_authority_unavailable')

    def test_all_direct_principal_kinds_and_issuer_key_substitution(self):
        for kind in ('human', 'device', 'service', 'plugin'):
            self.record['state']['identities'][0]['kind'] = kind
            self.env['operation']['caller']['kind'] = kind
            self.resign()
            self.assertEqual(self.check().outcome, 'allowed')
        self.env['ingressAttestation']['signature'] = sign_claims(
            self.env['ingressAttestation']['claims'], bytes(reversed(SEED)))
        with self.assertRaisesRegex(ContractError, 'signature_invalid'):
            self.check()


class ReaderTests(unittest.IsolatedAsyncioTestCase):
    def reader(self, js):
        return AuthorityReader(js, stream='IDENTITY', subject='identity.profile-one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')

    async def test_leader_read_and_recheck_revocation(self):
        record, env = fixture()
        js = SimpleNamespace(get_msg=AsyncMock(return_value=SimpleNamespace(
            subject='identity.profile-one', seq=1, data=canonical_bytes(record))))
        reader = self.reader(js)
        args = dict(audience={'hubId': 'hub-one', 'serviceId': 'task-owner'})
        clock = patch('identity.authority._utc_now')
        mocked = clock.start(); self.addCleanup(clock.stop); mocked.return_value = NOW
        self.assertEqual((await reader.evaluate(canonical_bytes(env), **args)).outcome, 'allowed')
        record['state']['grants'][0]['status'] = 'revoked'
        js.get_msg.return_value.data = canonical_bytes(record)
        self.assertEqual((await reader.evaluate(canonical_bytes(env), **args)).outcome, 'denied')
        js.get_msg.assert_awaited_with('IDENTITY', subject='identity.profile-one', direct=False)

    async def test_missing_state_is_unavailable_and_cancellation_propagates(self):
        js = SimpleNamespace(get_msg=AsyncMock(side_effect=RuntimeError('private broker detail')))
        with self.assertRaisesRegex(ContractError, '^authority_unavailable$'):
            await self.reader(js).current()
        js.get_msg.side_effect = asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError): await self.reader(js).current()

    async def test_wrong_profile_and_owner_are_rejected(self):
        record, _ = fixture()
        js = SimpleNamespace(get_msg=AsyncMock())
        for field, value, code in [('ownerHubId', 'other-hub', 'authority_owner_mismatch'),
                                   ('entityId', 'other-entity', 'authority_owner_mismatch')]:
            changed = copy.deepcopy(record); changed[field] = value
            js.get_msg.return_value = SimpleNamespace(subject='identity.profile-one', seq=1, data=canonical_bytes(changed))
            with self.assertRaisesRegex(ContractError, code): await self.reader(js).current()

    async def test_clock_is_sampled_after_authority_read(self):
        record, env = fixture()
        async def get_msg(*args, **kwargs):
            clock.return_value = NOW + timedelta(minutes=10)
            return SimpleNamespace(subject='identity.profile-one', seq=2, data=canonical_bytes(record))
        js = SimpleNamespace(get_msg=get_msg)
        with patch('identity.authority._utc_now', return_value=NOW) as clock:
            decision = await self.reader(js).evaluate(canonical_bytes(env),
                audience={'hubId': 'hub-one', 'serviceId': 'task-owner'})
        self.assertEqual(decision.reason, 'issuer_unavailable')

    async def test_profile_subject_and_malformed_message_refuse(self):
        record, _ = fixture()
        record['state']['profileId'] = 'other-profile'
        js = SimpleNamespace(get_msg=AsyncMock(return_value=SimpleNamespace(
            subject='identity.profile-one', seq=1, data=canonical_bytes(record))))
        with self.assertRaisesRegex(ContractError, 'authority_profile_mismatch'):
            await self.reader(js).current()
        for message in (SimpleNamespace(), SimpleNamespace(subject='other.subject', seq=1, data=b'{}')):
            js.get_msg.return_value = message
            with self.assertRaisesRegex(ContractError, 'authority_record_invalid'):
                await self.reader(js).current()
