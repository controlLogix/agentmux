"""Current approval rules for a fresh read of an expired Secret.Use operation."""
import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from identity import test_service as service_fixture
from identity.test_authority import NOW, SEED, ref
from identity.test_ordinary_secret import INTERVAL, SCOPE, resolution_fixture


class OrdinarySecretQueryApprovalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        service_fixture.ServiceTests.setUp(self)
        source, outer, _ = resolution_fixture()
        self.record['state'] = source['state']
        state = self.record['state']
        original_grant = next(row for row in state['grants']
                              if row['ref'] == ref('ordinary-use-grant'))
        original_grant['decision'] = 'review-required'
        state['identities'].append({'ref': ref('query-approver'), 'principalId': 'query-approver',
            'kind': 'human', 'status': 'active', 'externalIdentity': None})
        state['memberships'].append({'ref': ref('query-approver-member'),
            'identityRef': ref('query-approver'), 'scope': copy.deepcopy(SCOPE), 'status': 'active'})
        state['grants'].append({**copy.deepcopy(original_grant), 'ref': ref('original-approver-grant'),
            'callerRef': ref('query-approver'), 'actorRef': ref('query-approver'),
            'contractId': 'identity-approve', 'resourceId': original_grant['ref']['id'],
            'decision': 'allowed'})
        state['grants'].append({**copy.deepcopy(original_grant), 'ref': ref('fresh-query-grant'),
            'contractId': 'capability-outcome-query', 'decision': 'allowed'})
        self.original = copy.deepcopy(outer['payload']['originalEnvelope'])
        operation = self.original['operation']
        self.approval = {'ref': ref('original-approval'), 'grantRef': copy.deepcopy(original_grant['ref']),
            'approverRef': ref('query-approver'), 'approverGrantRef': ref('original-approver-grant'),
            'payloadDigest': operation['payloadDigest'],
            'audience': {'hubId': 'hub-one', 'serviceId': 'secret-owner'},
            'operationId': operation['operationId'], 'expectedVersion': 1,
            'decision': 'approved', **INTERVAL}
        state['approvals'].append(self.approval)
        operation['approvalRefs'] = [self.approval['ref']]
        claims = self.original['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(operation)
        self.original['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        self.later = datetime.fromisoformat(operation['deadline']) + timedelta(seconds=1)
        self.query_claims = {**copy.deepcopy(self.claims), 'operationId': 'fresh-approved-secret-query',
            'grantRef': ref('fresh-query-grant'), 'expectedVersion': 1,
            'contractId': 'capability-outcome-query', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'contractId': 'capability-secret-use', 'operationId': operation['operationId'],
                    'payloadDigest': operation['payloadDigest']}},
            'issuedAt': self.later.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (self.later + timedelta(seconds=20)).isoformat().replace('+00:00', 'Z')}
        self._baseline = copy.deepcopy(state)
        self.addAsyncCleanup(self.service.close)

    def store(self):
        self.js.messages = [SimpleNamespace(subject=self.service.ledger._subject, seq=1,
            data=canonical_bytes(self.record))]

    def row(self, collection, name):
        return next(row for row in self.record['state'][collection] if row['ref']['id'] == name)

    async def decision(self):
        self.store()
        later = self.later
        class Later(service_fixture._Clock):
            @classmethod
            def now(cls, tz=None):
                return later
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': self.query_claims,
            'signature': sign_claims(self.query_claims, bytes(reversed(SEED)))})
        with patch('identity.ingress.datetime', Later), \
                patch('identity.authority._utc_now', return_value=later):
            admitted = await self.service.ingress.admit(request, cancellation_ref=ref('query-cancel'))
            if admitted.envelope is not None:
                current = await self.service.reader.evaluate(admitted.envelope,
                    audience={'hubId': 'hub-one', 'serviceId': 'outcome-owner'})
                self.assertEqual(current.outcome, admitted.decision.outcome)
            return admitted.decision

    async def assert_refused(self):
        try:
            decision = await self.decision()
        except ContractError:
            return
        self.assertNotEqual(decision.outcome, 'allowed')

    async def test_fresh_query_uses_current_exact_approval_without_extending_original(self):
        self.store()
        original = canonical_bytes(self.original)
        with patch('identity.authority._utc_now', return_value=NOW):
            admitted = await self.service.reader.evaluate(original,
                audience={'hubId': 'hub-one', 'serviceId': 'secret-owner'})
        self.assertEqual(admitted.outcome, 'allowed')
        self.assertLess(self.later, datetime.fromisoformat(self.approval['expiresAt']))
        self.assertEqual((await self.decision()).outcome, 'allowed')
        with patch('identity.authority._utc_now', return_value=self.later), self.assertRaises(ContractError):
            await self.service.reader.evaluate(original,
                audience={'hubId': 'hub-one', 'serviceId': 'secret-owner'})
        self.assertEqual(canonical_bytes(self.original), original)
        self.assertEqual(len(self.js.messages), 1)

    async def test_approval_must_be_present_current_approved_and_exact(self):
        mutations = (
            ('absent', lambda a: self.record['state'].update(approvals=[])),
            ('rejected', lambda a: a.update(decision='rejected')),
            ('revoked', lambda a: a.update(status='revoked')),
            ('expired', lambda a: a.update(expiresAt=self.later.isoformat())),
            ('future', lambda a: a.update(issuedAt=(self.later + timedelta(seconds=1)).isoformat())),
            ('operation', lambda a: a.update(operationId='other-original')),
            ('digest', lambda a: a.update(payloadDigest='sha256:' + 'f' * 64)),
            ('version', lambda a: a.update(expectedVersion=2)),
            ('audience', lambda a: a['audience'].update(serviceId='outcome-owner')),
            ('grant', lambda a: a.update(grantRef=ref('fresh-query-grant'))),
            ('grant-revision', lambda a: a['grantRef'].update(revision=2)),
            ('approver', lambda a: a.update(approverRef=ref('unavailable-approver'))),
            ('approver-grant', lambda a: a.update(approverGrantRef=ref('fresh-query-grant'))),
        )
        for name, mutate in mutations:
            self.record['state'] = copy.deepcopy(self._baseline)
            mutate(self.record['state']['approvals'][0])
            with self.subTest(field=name):
                await self.assert_refused()

    async def test_approver_requires_current_identity_membership_and_approval_grant(self):
        mutations = (
            ('identity', lambda: self.row('identities', 'query-approver').update(status='revoked')),
            ('membership', lambda: self.row('memberships', 'query-approver-member').update(status='revoked')),
            ('membership-scope', lambda: self.row('memberships', 'query-approver-member')['scope'].update(projectId='other-project')),
            ('grant-revoked', lambda: self.row('grants', 'original-approver-grant').update(status='revoked')),
            ('grant-expired', lambda: self.row('grants', 'original-approver-grant').update(expiresAt=self.later.isoformat())),
            ('grant-denied', lambda: self.row('grants', 'original-approver-grant').update(decision='denied')),
            ('grant-caller', lambda: self.row('grants', 'original-approver-grant').update(callerRef=ref('human'))),
            ('grant-actor', lambda: self.row('grants', 'original-approver-grant').update(actorRef=ref('human'))),
            ('grant-contract', lambda: self.row('grants', 'original-approver-grant').update(contractId='task-inspect')),
            ('grant-resource', lambda: self.row('grants', 'original-approver-grant').update(resourceId='other-grant')),
            ('grant-scope', lambda: self.row('grants', 'original-approver-grant')['scope'].update(projectId='other-project')),
            ('grant-delegation', lambda: self.row('grants', 'original-approver-grant').update(delegationRef=ref('delegation'))),
        )
        for name, mutate in mutations:
            self.record['state'] = copy.deepcopy(self._baseline)
            mutate()
            with self.subTest(field=name):
                await self.assert_refused()

    async def test_original_query_and_approver_hard_denials_override_approval(self):
        for name in ('ordinary-use-grant', 'fresh-query-grant', 'original-approver-grant'):
            self.record['state'] = copy.deepcopy(self._baseline)
            denied = copy.deepcopy(self.row('grants', name))
            denied.update(ref=ref('additional-hard-denial'), decision='denied')
            self.record['state']['grants'].append(denied)
            with self.subTest(grant=name):
                await self.assert_refused()

    async def test_separately_current_query_and_original_authority_are_required(self):
        for collection, name in (('grants', 'ordinary-use-grant'), ('grants', 'fresh-query-grant'),
                                 ('identities', 'human'), ('transports', 'transport')):
            self.record['state'] = copy.deepcopy(self._baseline)
            self.row(collection, name)['status'] = 'revoked'
            with self.subTest(collection=collection, ref=name):
                await self.assert_refused()

    async def test_original_fields_are_distinct_from_query_proof_and_other_families(self):
        original_claims = copy.deepcopy(self.query_claims)
        for field, value in (('operationId', 'different-original'),
                             ('payloadDigest', 'sha256:' + 'd' * 64)):
            self.query_claims = copy.deepcopy(original_claims)
            self.query_claims['payload']['input'][field] = value
            with self.subTest(original_field=field):
                await self.assert_refused()
        self.query_claims = copy.deepcopy(original_claims)
        self.query_claims['payload']['resourceRef']['revision'] = 2
        self.record['state']['approvals'][0]['expectedVersion'] = 2
        await self.assert_refused()
        self.record['state'] = copy.deepcopy(self._baseline)
        self.query_claims = copy.deepcopy(original_claims)
        self.query_claims['payload']['input']['contractId'] = 'capability-storage-read'
        self.row('grants', 'ordinary-use-grant')['contractId'] = 'capability-storage-read'
        self.record['state']['approvals'][0]['audience']['serviceId'] = 'storage-owner'
        await self.assert_refused()

    async def test_allowed_originals_remain_supported_without_an_approval(self):
        self.row('grants', 'ordinary-use-grant')['decision'] = 'allowed'
        self.record['state']['approvals'] = []
        self.assertEqual((await self.decision()).outcome, 'allowed')

    async def test_query_approval_cannot_replace_the_original_approval(self):
        self.row('grants', 'fresh-query-grant')['decision'] = 'review-required'
        query_grant = copy.deepcopy(self.row('grants', 'original-approver-grant'))
        query_grant.update(ref=ref('query-approver-grant'), resourceId='fresh-query-grant')
        self.record['state']['grants'].append(query_grant)
        query_approval = {**copy.deepcopy(self.approval), 'ref': ref('query-approval'),
            'grantRef': ref('fresh-query-grant'), 'approverGrantRef': query_grant['ref'],
            'operationId': self.query_claims['operationId'],
            'payloadDigest': payload_digest(self.query_claims['payload']),
            'audience': {'hubId': 'hub-one', 'serviceId': 'outcome-owner'}}
        self.record['state']['approvals'].append(query_approval)
        await self.assert_refused()
        self.query_claims['approvalRefs'] = [query_approval['ref']]
        self.assertEqual((await self.decision()).outcome, 'allowed')
        self.record['state']['approvals'] = [query_approval]
        await self.assert_refused()


if __name__ == '__main__':
    unittest.main()
