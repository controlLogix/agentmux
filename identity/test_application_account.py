"""Application account metadata and current owner-authorized reference resolution."""
import copy
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from sdk.python.tests.test_contracts import NOW, SEED

from identity.application_account import ApplicationAccountAuthority, resolve_snapshot
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader
from identity.test_authority import fixture, ref
from identity.test_transitions import ACCOUNT
from identity.transitions import transition


class ApplicationAccountTests(unittest.TestCase):
    def setUp(self):
        self.record, self.request = fixture()
        state = self.record['state']
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        interval = {'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
                    'expiresAt': '2026-10-09T12:10:00Z'}
        admin = {'ref': ref('account-admin'), 'principalId': 'application-account-admin',
                 'kind': 'service', 'status': 'active', 'externalIdentity': None}
        state['identities'].append(admin)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('account-admin-transport'), identityRef=admin['ref'])
        state['transports'].append(transport)
        state['memberships'].append({'ref': ref('account-admin-member'),
            'identityRef': admin['ref'], 'scope': self.scope, 'status': 'active'})
        credential = {'ref': ref('account-admin-credential'),
            'kind': 'nats-administrator-credential', 'scope': self.scope,
            'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        issuer = {'ref': ref('account-issuer-secret'), 'kind': 'nats-account-issuer',
            'scope': self.scope, 'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        account = {'ref': ref('application-account'), 'profileId': 'profile-one',
            'scope': self.scope, 'accountPublicKey': ACCOUNT,
            'administratorIdentityRef': admin['ref'],
            'administratorTransportRef': transport['ref'],
            'administratorCredentialRef': credential['ref'], 'accountIssuerRef': issuer['ref'], **interval}
        state = transition(state, 'identity-application-account-set', {
            'authorityId': 'authority-one', 'record': account, 'previousRef': None,
            'administratorCredential': {'record': credential, 'previousRef': None},
            'accountIssuer': {'record': issuer, 'previousRef': None}}, hub_id='hub-one')
        self.record['state'] = state
        self.payload = {'authorityId': 'authority-one', 'accountRef': account['ref'],
            'profileId': 'profile-one', 'scope': self.scope, 'accountPublicKey': ACCOUNT}
        operation = self.request['operation']
        operation.update(scope=self.scope, expectedVersion=0, grantRef=ref('account-resolve-grant'),
                         approvalRefs=[], payloadDigest=payload_digest(self.payload))
        operation['caller']['authenticatedIdentityRef'] = ref('human')
        operation['effectiveActorRef'] = ref('human')
        state['memberships'][0]['scope'] = self.scope
        state['grants'][0].update(ref=ref('account-resolve-grant'), scope=self.scope,
            contractId='identity-application-account-resolve', resourceId='application-account',
            decision='allowed')
        self.request.update(contractId='identity-application-account-resolve',
            destinationServiceId='identity-owner', payload=self.payload)
        self.resign()

    def resign(self):
        claims = self.request['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(self.request['operation']),
            contractId=self.request['contractId'])
        claims['audience']['serviceId'] = 'identity-owner'
        self.request['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    def resolve(self):
        return resolve_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 23),
            canonical_bytes(self.request), audience={'hubId': 'hub-one', 'serviceId': 'identity-owner'}, now=NOW)

    def test_returns_only_exact_public_references_with_signed_deadline(self):
        result = self.resolve()
        self.assertEqual((result.account_ref, result.account_public_key),
                         (ref('application-account'), ACCOUNT))
        self.assertEqual(result.administrator_credential_ref, ref('account-admin-credential'))
        self.assertEqual(result.account_issuer_ref, ref('account-issuer-secret'))
        self.assertEqual(result.authority_sequence, 23)
        self.assertNotIn('secret', repr(result))

        issuer = copy.deepcopy(self.record['state']['issuers'][0])
        issuer.update(ref=ref('account-admin-issuer'), identityRef=ref('account-admin'),
                      expiresAt='2026-10-09T12:04:00Z')
        self.record['state']['issuers'].append(issuer)
        self.record['state']['transports'][-1]['issuerRef'] = issuer['ref']
        self.assertEqual(self.resolve().valid_until,
                         datetime.fromisoformat('2026-10-09T12:04:00Z'))

    def test_substitution_revocation_and_hard_denial_refuse(self):
        original_record, original_payload = copy.deepcopy(self.record), copy.deepcopy(self.payload)

        def revoke_administrator_issuer():
            issuer = copy.deepcopy(self.record['state']['issuers'][0])
            issuer.update(ref=ref('account-admin-issuer'), identityRef=ref('account-admin'),
                          status='revoked')
            self.record['state']['issuers'].append(issuer)
            self.record['state']['transports'][-1]['issuerRef'] = issuer['ref']

        changes = (
            lambda: self.request['payload'].update(accountPublicKey='A' * 56),
            lambda: self.record['state']['applicationAccounts'][0].update(status='revoked'),
            lambda: self.record['state']['secretReferences'][0].update(status='revoked'),
            revoke_administrator_issuer,
            lambda: self.record['state']['memberships'][-1].update(status='revoked'),
            lambda: self.record['state']['grants'].append({**copy.deepcopy(self.record['state']['grants'][0]),
                'ref': ref('account-hard-denial'), 'decision': 'denied'}))
        for change in changes:
            with self.subTest(change=change):
                self.record, self.payload = copy.deepcopy(original_record), copy.deepcopy(original_payload)
                self.request['payload'] = self.payload
                change(); self.resign()
                with self.assertRaises(ContractError):
                    self.resolve()

    def test_review_required_uses_existing_exact_approval_semantics(self):
        grant = self.record['state']['grants'][0]
        grant['decision'] = 'review-required'
        with self.assertRaisesRegex(ContractError, 'application_account_not_authorized'):
            self.resolve()
        approval_grant = copy.deepcopy(grant)
        approval_grant.update(ref=ref('account-approval-grant'), contractId='identity-approve',
                              resourceId=grant['ref']['id'], decision='allowed')
        self.record['state']['grants'].append(approval_grant)
        approval = {'ref': ref('account-approval'), 'grantRef': grant['ref'],
            'approverRef': ref('human'), 'approverGrantRef': approval_grant['ref'],
            'payloadDigest': self.request['operation']['payloadDigest'],
            'audience': {'hubId': 'hub-one', 'serviceId': 'identity-owner'},
            'operationId': self.request['operation']['operationId'], 'expectedVersion': 0,
            'decision': 'approved', 'status': 'active',
            'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z'}
        self.record['state']['approvals'].append(approval)
        self.request['operation']['approvalRefs'] = [approval['ref']]
        self.resign()
        self.assertEqual(self.resolve().account_ref, ref('application-account'))


class ApplicationAccountAuthorityTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolution_uses_time_after_current_authority_read(self):
        case = ApplicationAccountTests()
        case.setUp()
        reader = object.__new__(LedgerAuthorityReader)
        reader._hub = 'hub-one'

        async def current():
            return AuthoritySnapshot(canonical_bytes(case.record), 23)

        reader.current = current
        clock = datetime.fromisoformat('2026-10-09T12:11:00Z')
        with patch('identity.application_account.datetime') as mocked_datetime:
            mocked_datetime.now.return_value = clock
            mocked_datetime.fromisoformat.side_effect = datetime.fromisoformat
            with self.assertRaises(ContractError):
                await ApplicationAccountAuthority(reader).resolve(canonical_bytes(case.request))
            mocked_datetime.now.assert_called_once_with(timezone.utc)


if __name__ == '__main__':
    unittest.main()
