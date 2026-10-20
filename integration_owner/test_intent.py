"""Offline intent checks; installed composition and dispatch remain unavailable.

Reuse existing fault controls to check the real ledger. These controls do not
qualify a broker or replace signed integration authority.
"""
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from integration_owner.intent import effect_id, intent, query, retained_state
from integration_owner.receiver import IntegrationOwner
from identity.authority import AuthorityReader
from identity.test_authority import fixture
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream, CREATED, SCOPE, record


BINDING = OwnerBinding('hub-one', 'integrations', effect_id(SCOPE, 'operation-one'), 'effect', canonical_bytes(SCOPE))


def payload():
    return {'effectRef': {'id': BINDING.entity_id, 'ownerHubId': 'hub-one', 'revision': 0},
            'credentialRef': {'id': 'jira-account', 'ownerHubId': 'hub-one', 'revision': 1},
            'action': 'jira-transition', 'target': {'issueKey': 'AMUX-66', 'transitionId': '31'},
            'contentRef': None}


def intent_record():
    value = record()
    body = payload()
    value.update(entityId=BINDING.entity_id, entityKind='effect', ownerDomain='integrations')
    value['operation']['payloadDigest'] = payload_digest(body)
    value['operation']['approvalRefs'] = [{'id': 'approval-one', 'ownerHubId': 'hub-one', 'revision': 1}]
    value['state'] = {'format': 'amx-integration-effect-v1', 'phase': 'intent-committed',
        'originalOperationId': value['operation']['operationId'],
        'originalPayloadDigest': value['operation']['payloadDigest'], 'intent': body}
    value['authorizationDecision'] = {'operationId': value['operation']['operationId'],
        'decision': 'allowed', 'reason': 'authorized',
        'actorRef': value['operation']['effectiveActorRef'], 'contractId': 'integration-intent'}
    value['effects'] = [{'effectId': BINDING.entity_id, 'contractId': 'integration-intent',
        'payloadDigest': value['operation']['payloadDigest'], 'grantRef': value['operation']['grantRef'],
        'recovery': 'query-before-retry', 'payload': body}]
    return value


class IntentTests(unittest.TestCase):
    def test_original_operation_has_one_effect_aggregate_per_scope(self):
        first = effect_id(SCOPE, 'original-write')
        self.assertEqual(first, effect_id(copy.deepcopy(SCOPE), 'original-write'))
        self.assertNotEqual(first, effect_id(SCOPE, 'another-write'))
        self.assertNotEqual(first, effect_id({**SCOPE, 'projectId': 'another-project'}, 'original-write'))

    def test_exact_target_and_credential_reference_preserved(self):
        original = payload()
        result = intent(original)
        self.assertEqual(result, original)
        original['target']['issueKey'] = 'OTHER-1'
        self.assertEqual(result['target']['issueKey'], 'AMUX-66')

    def test_authority_secret_and_remote_status_claims_refused(self):
        for field in ('actor', 'approved', 'api_token', 'outcome', 'externalId', 'grantRef'):
            value = payload()
            value[field] = 'synthetic-private-value'
            with self.assertRaises(ContractError):
                intent(value)

    def test_target_ids_and_version_types_refused(self):
        for target in ({'issueKey': '../AMUX-66', 'transitionId': '31'},
                       {'issueKey': 'AMUX-66', 'transitionId': '../31'},
                       {'issueKey': 'AMUX-66', 'transitionId': True}):
            with self.assertRaises(ContractError):
                intent({**payload(), 'target': target})
        with self.assertRaises(ContractError):
            intent({**payload(), 'action': 'confluence-update', 'target': {
                'spaceKey': 'DOCS', 'pageId': '42', 'expectedVersion': True}})

    def test_content_is_a_reference_and_required_for_comments(self):
        value = {**payload(), 'action': 'jira-comment', 'target': {'issueKey': 'AMUX-66'}}
        for content in (None, {'path': '/private/file'}, {'api_token': 'synthetic-private'}):
            with self.assertRaises(ContractError):
                intent({**value, 'contentRef': content})

    def test_query_preserves_original_identity_and_refuses_result_claim(self):
        body = {'effectRef': payload()['effectRef'], 'originalOperationId': 'operation-one',
                'originalPayloadDigest': payload_digest(payload())}
        self.assertEqual(query(body), body)
        with self.assertRaises(ContractError):
            query({**body, 'status': 'applied'})

    def test_retained_intent_checks_digest_audit_and_exact_effect(self):
        value = intent_record()
        self.assertEqual(retained_state(value)['phase'], 'intent-committed')
        for field in ('state', 'effects', 'authorizationDecision'):
            changed = copy.deepcopy(value)
            if field == 'state':
                changed[field]['intent']['target']['issueKey'] = 'OTHER-1'
            elif field == 'effects':
                changed[field][0]['recovery'] = 'idempotent-retry'
            else:
                changed[field]['decision'] = 'denied'
            with self.assertRaises(ContractError):
                retained_state(changed)

    def test_retained_intent_requires_original_approval_reference(self):
        value = intent_record()
        value['operation']['approvalRefs'] = []
        with self.assertRaises(ContractError):
            retained_state(value)

    def test_retained_intent_requires_original_zero_version(self):
        value = intent_record()
        value['operation']['expectedVersion'] = 1
        with self.assertRaises(ContractError):
            retained_state(value)


class ReceivingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = Retention(2097152, 262144)
        self.js = FakeJetStream(self.policy)
        self.js.config.subjects = [owner_subject(BINDING)]
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=owner_subject(BINDING),
            binding=BINDING, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        self.authority = AuthorityReader(self.js, stream='AUTHORITY', subject='authority.one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')

    def test_arbitrary_authorizer_callback_is_not_configuration(self):
        with self.assertRaises(ContractError):
            IntegrationOwner(lambda *_: True, self.ledger, BINDING,
                             provider='jira', credential_ref=payload()['credentialRef'])

    def test_authority_hub_and_organization_must_match_enrolled_owner(self):
        for field in ('_hub', '_organization'):
            original = getattr(self.authority, field)
            setattr(self.authority, field, 'different-owner')
            with self.assertRaises(ContractError):
                IntegrationOwner(self.authority, self.ledger, BINDING,
                    provider='jira', credential_ref=payload()['credentialRef'])
            setattr(self.authority, field, original)

    async def test_tampered_intent_never_publishes(self):
        owner = IntegrationOwner(self.authority, self.ledger, BINDING,
                                 provider='jira', credential_ref=payload()['credentialRef'])
        _, envelope = fixture()
        envelope.update(contractId='integration-intent', destinationServiceId='integration-owner', payload=payload())
        with self.assertRaises(ContractError):
            await owner.handle(canonical_bytes(envelope))
        self.assertEqual(self.js.messages, [])

    async def test_real_ledger_lost_ack_retains_one_original_intent(self):
        value = intent_record()
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, 'owner_commit_uncertain'):
            await self.ledger.append(value, expected_sequence=0, completion_records=3)
        stored = await self.ledger.outcome(value['operation']['operationId'], value['operation']['payloadDigest'])
        self.assertEqual(retained_state(strict_loads(stored.record))['intent'], payload())
        self.assertEqual(len(self.js.messages), 1)
        changed = copy.deepcopy(value)
        changed['operation']['payloadDigest'] = payload_digest({'different': True})
        with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
            await self.ledger.outcome(changed['operation']['operationId'], changed['operation']['payloadDigest'])
        self.assertEqual(len(self.js.messages), 1)


if __name__ == '__main__':
    unittest.main()
