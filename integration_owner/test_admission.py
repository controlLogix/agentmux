"""Actual signing, authority and ledger APIs with offline broker fault controls."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from identity.authority import AuthorityReader
from identity.test_authority import fixture, ref, SEED
from integration_owner.intent import effect_id
from integration_owner.receiver import IntegrationOwner
from integration_owner.test_intent import payload
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream, CREATED, SCOPE


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record, self.envelope = fixture()
        now = datetime.now(timezone.utc)
        stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
        issued, expires = stamp(now - timedelta(seconds=10)), stamp(now + timedelta(minutes=5))
        self.envelope.update(contractId='integration-intent', destinationServiceId='integration-owner',
                             payload=payload(), sentAt=issued)
        operation = self.envelope['operation']
        operation.update(operationId='operation-one', scope=copy.deepcopy(SCOPE), expectedVersion=0,
            deadline=expires, payloadDigest=payload_digest(payload()), approvalRefs=[ref('approval')])
        self.binding = OwnerBinding('hub-one', 'integrations', effect_id(SCOPE, 'operation-one'),
                                     'effect', canonical_bytes(SCOPE))
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(SCOPE)
        for collection in ('issuers', 'transports', 'grants'):
            for item in state[collection]:
                item.update(issuedAt=issued, expiresAt=expires)
        grant = state['grants'][0]
        grant.update(contractId='integration-intent', resourceId=self.binding.entity_id, scope=copy.deepcopy(SCOPE))
        approver = copy.deepcopy(grant)
        approver.update(ref=ref('approve-grant'), contractId='identity-approve', resourceId=grant['ref']['id'])
        state['grants'].append(approver)
        state['approvals'] = [{'ref': ref('approval'), 'grantRef': grant['ref'],
            'approverRef': ref('human'), 'approverGrantRef': ref('approve-grant'),
            'operationId': operation['operationId'], 'payloadDigest': operation['payloadDigest'],
            'expectedVersion': 0, 'audience': {'hubId': 'hub-one', 'serviceId': 'integration-owner'},
            'decision': 'approved', 'status': 'active', 'issuedAt': issued, 'expiresAt': expires}]
        self.envelope['ingressAttestation']['claims'].update(issuedAt=issued, expiresAt=expires, sentAt=issued)
        self.resign()
        self.reads = 0
        async def authority_message(*args, **kwargs):
            self.reads += 1
            return SimpleNamespace(subject='authority.one', seq=17, data=canonical_bytes(self.record))
        self.authority_js = SimpleNamespace(get_msg=AsyncMock(side_effect=authority_message))
        self.authority = AuthorityReader(self.authority_js, stream='AUTHORITY', subject='authority.one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        policy = Retention(2097152, 262144)
        self.js = FakeJetStream(policy)
        self.js.config.subjects = [owner_subject(self.binding)]
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=policy, stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=payload()['credentialRef'])

    def resign(self):
        claims = self.envelope['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(self.envelope['operation']),
            contractId=self.envelope['contractId'],
            audience={'hubId': 'hub-one', 'serviceId': self.envelope['destinationServiceId']})
        self.envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    async def execute(self):
        return await self.owner.handle(canonical_bytes(self.envelope))

    def select_query(self, original):
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('query-grant'), contractId='integration-effect-query')
        self.record['state']['grants'].append(grant)
        self.envelope.update(contractId='integration-effect-query', payload={
            'effectRef': {'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': 1},
            'originalOperationId': original.operation_id, 'originalPayloadDigest': original.original_payload_digest})
        self.envelope['operation'].update(operationId='query-one', expectedVersion=1,
            payloadDigest=payload_digest(self.envelope['payload']), grantRef=ref('query-grant'), approvalRefs=[])
        self.resign()

    async def test_signed_approved_intent_is_retained_once_and_replay_preserves_identity(self):
        first = await self.execute()
        second = await self.execute()
        self.assertEqual((first.status, second.status), ('intent-committed', 'intent-committed'))
        self.assertEqual(first.original_operation_id, second.original_operation_id)
        self.assertEqual(len(self.js.messages), 1)
        self.assertGreaterEqual(self.reads, 5)

    async def test_lost_ack_queries_original_identity_without_duplicate_append(self):
        self.js.lose_ack = True
        result = await self.execute()
        self.assertEqual(result.status, 'intent-committed')
        self.assertEqual(len(self.js.messages), 1)

    async def test_uncertain_append_with_absent_outcome_never_retries(self):
        with patch.object(self.js, 'publish', new=AsyncMock(side_effect=TimeoutError('synthetic-private')) ) as publish:
            with self.assertRaisesRegex(ContractError, '^integration_reconciliation_required$'):
                await self.execute()
        self.assertEqual(publish.await_count, 1)
        self.assertEqual(self.js.messages, [])

    async def test_changed_intent_reuse_cannot_get_another_aggregate_or_append(self):
        await self.execute()
        self.envelope['payload']['target']['transitionId'] = '41'
        digest = payload_digest(self.envelope['payload'])
        self.envelope['operation']['payloadDigest'] = digest
        self.record['state']['approvals'][0]['payloadDigest'] = digest
        self.resign()
        with self.assertRaisesRegex(ContractError, '^integration_original_identity_conflict$'):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)

    async def test_missing_approval_and_revocation_stop_before_append(self):
        self.envelope['operation']['approvalRefs'] = []
        self.resign()
        with self.assertRaises(ContractError):
            await self.execute()
        self.envelope['operation']['approvalRefs'] = [ref('approval')]
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.resign()
        with self.assertRaises(ContractError):
            await self.execute()
        self.assertEqual(self.js.messages, [])

    async def test_query_uses_one_snapshot_and_cannot_reuse_original_operation_id(self):
        original = await self.execute()
        self.select_query(original)
        with patch.object(self.ledger, 'outcome', side_effect=AssertionError('separate snapshot lookup refused')):
            result = await self.execute()
        self.assertEqual((result.status, result.sequence), ('intent-committed', 1))
        self.envelope['operation']['operationId'] = original.operation_id
        self.resign()
        with self.assertRaises(ContractError):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)

    async def test_revocation_immediately_before_append_blocks_commit(self):
        original_read = self.authority_js.get_msg.side_effect
        async def revoke(*args, **kwargs):
            if self.reads == 1:
                self.record['state']['grants'][0]['status'] = 'revoked'
            return await original_read(*args, **kwargs)
        self.authority_js.get_msg.side_effect = revoke
        with self.assertRaises(ContractError):
            await self.execute()
        self.assertEqual(self.js.messages, [])

    async def test_revocation_before_reply_withholds_the_committed_intent_receipt(self):
        original_read = self.authority_js.get_msg.side_effect
        async def revoke(*args, **kwargs):
            if self.reads == 2:
                self.record['state']['grants'][0]['status'] = 'revoked'
            return await original_read(*args, **kwargs)
        self.authority_js.get_msg.side_effect = revoke
        with self.assertRaisesRegex(ContractError, '^integration_access_refused$'):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)


if __name__ == '__main__':
    unittest.main()
