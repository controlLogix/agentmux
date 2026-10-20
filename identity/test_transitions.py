"""Offline pure transitions with real application-key possession signatures."""
import base64
import copy
import unittest

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, sign_claims
from identity.test_authority import fixture, ref
from identity.transitions import transition

SEED = bytes(range(32))
PUBLIC = base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
ACCOUNT = 'AAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB776S'


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()[0]['state']
        self.before = copy.deepcopy(self.state)

    def call(self, command, payload):
        return transition(self.state, command, payload, hub_id='hub-one')

    def proof(self, item, *, profile='profile-one', authority='authority-one'):
        return {'record': item, 'proof': sign_claims({
            'purpose': 'agentmux-enrollment-possession-v1', 'profileId': profile,
            'authorityId': authority, 'credential': item}, SEED)}

    def enrollment(self):
        identity = copy.deepcopy(self.state['identities'][0])
        identity.update(ref=ref('new-human'), principalId='new-user')
        transport = copy.deepcopy(self.state['transports'][0])
        transport.update(ref=ref('new-transport'), identityRef=identity['ref'], publicKey=PUBLIC)
        return {'authorityId': 'authority-one', 'identity': identity, 'issuers': [],
                'transports': [self.proof(transport)]}

    def application_account(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        admin = {'ref': ref('account-admin'), 'principalId': 'application-account-admin',
                 'kind': 'service', 'status': 'active', 'externalIdentity': None}
        self.state['identities'].append(admin)
        transport = copy.deepcopy(self.state['transports'][0])
        transport.update(ref=ref('account-admin-transport'), identityRef=admin['ref'])
        self.state['transports'].append(transport)
        self.state['memberships'].append({'ref': ref('account-admin-member'),
            'identityRef': admin['ref'], 'scope': scope, 'status': 'active'})
        interval = {'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
                    'expiresAt': '2026-10-09T12:10:00Z'}
        credential = {'ref': ref('account-admin-credential'),
            'kind': 'nats-administrator-credential', 'scope': scope,
            'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        issuer = {'ref': ref('account-issuer-secret'), 'kind': 'nats-account-issuer',
            'scope': scope, 'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        record = {'ref': ref('application-account'), 'profileId': 'profile-one',
            'scope': scope, 'accountPublicKey': ACCOUNT,
            'administratorIdentityRef': admin['ref'],
            'administratorTransportRef': transport['ref'],
            'administratorCredentialRef': credential['ref'],
            'accountIssuerRef': issuer['ref'], **interval}
        return {'authorityId': 'authority-one', 'record': record, 'previousRef': None,
            'administratorCredential': {'record': credential, 'previousRef': None},
            'accountIssuer': {'record': issuer, 'previousRef': None}}

    def test_enroll_with_real_possession_and_no_input_alias(self):
        payload = self.enrollment()
        saved = copy.deepcopy(payload)
        result = self.call('identity-enroll', payload)
        self.assertEqual(result['identities'][-1]['principalId'], 'new-user')
        self.assertEqual(self.state, self.before)
        self.assertEqual(payload, saved)
        result['identities'][-1]['principalId'] = 'changed'
        self.assertEqual(payload, saved)
        result['identities'][0]['principalId'] = 'changed'
        self.assertEqual(self.state, self.before)

    def test_every_identity_kind_enrolls_with_possession_and_revokes_retained_record(self):
        for kind in ('human', 'device', 'service', 'plugin'):
            with self.subTest(kind=kind):
                self.setUp()
                payload = self.enrollment()
                payload['identity'].update(kind=kind, principalId='new-' + kind)
                enrolled = self.call('identity-enroll', payload)
                identity = enrolled['identities'][-1]
                self.assertEqual((identity['kind'], identity['status']), (kind, 'active'))
                self.assertEqual(enrolled['transports'][-1]['identityRef'], identity['ref'])

                revoked = transition(enrolled, 'identity-revoke', {
                    'authorityId': 'authority-one', 'targetRef': identity['ref']},
                    hub_id='hub-one')
                retained = revoked['identities'][-1]
                self.assertEqual((retained['kind'], retained['status']), (kind, 'revoked'))
                self.assertEqual(retained['ref']['revision'], 2)
                self.assertEqual(self.state, self.before)

    def test_possession_binds_record_profile_and_authority(self):
        for change in ('record', 'profile', 'authority', 'signature'):
            with self.subTest(change=change):
                payload = self.enrollment()
                credential = payload['transports'][0]
                if change == 'record':
                    credential['record']['ref']['id'] = 'different-transport'
                elif change == 'profile':
                    payload['transports'][0] = self.proof(credential['record'], profile='different-profile')
                elif change == 'authority':
                    payload['authorityId'] = 'different-authority'
                else:
                    credential['proof'] = sign_claims({'different': True}, SEED)
                with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
                    self.call('identity-enroll', payload)
                self.assertEqual(self.state, self.before)

    def test_additional_credentials_require_exact_existing_active_identity(self):
        payload = self.enrollment()
        payload['identity'] = copy.deepcopy(self.state['identities'][0])
        payload['transports'][0]['record']['identityRef'] = payload['identity']['ref']
        payload['transports'][0] = self.proof(payload['transports'][0]['record'])
        result = self.call('identity-enroll', payload)
        self.assertEqual(len(result['identities']), len(self.state['identities']))
        payload['identity']['principalId'] = 'changed-user'
        with self.assertRaisesRegex(ContractError, 'identity_enrollment_conflict'):
            self.call('identity-enroll', payload)
        payload['identity'] = copy.deepcopy(self.state['identities'][0])
        self.state['identities'][0]['status'] = 'revoked'
        payload['identity']['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'identity_enrollment_conflict'):
            self.call('identity-enroll', payload)

    def test_identity_and_reference_collisions_are_denied(self):
        payload = self.enrollment()
        payload['identity']['principalId'] = self.state['identities'][0]['principalId']
        with self.assertRaisesRegex(ContractError, 'authority_principal_ambiguous'):
            self.call('identity-enroll', payload)
        payload = self.enrollment()
        payload['identity']['ref'] = ref('member')
        with self.assertRaisesRegex(ContractError, 'identity_enrollment_conflict'):
            self.call('identity-enroll', payload)
        payload = self.enrollment()
        payload['transports'].append(copy.deepcopy(payload['transports'][0]))
        with self.assertRaisesRegex(ContractError, 'identity_reference_exists'):
            self.call('identity-enroll', payload)

    def test_issuer_requires_service_and_transport_rejects_oidc(self):
        payload = self.enrollment()
        issuer = copy.deepcopy(self.state['issuers'][0])
        issuer.update(ref=ref('new-issuer'), identityRef=payload['identity']['ref'], publicKey=PUBLIC)
        payload['issuers'] = [self.proof(issuer)]
        with self.assertRaisesRegex(ContractError, 'identity_issuer_service_required'):
            self.call('identity-enroll', payload)
        payload['identity']['kind'] = 'service'
        payload['transports'][0]['record']['issuerRef'] = issuer['ref']
        payload['transports'][0] = self.proof(payload['transports'][0]['record'])
        result = self.call('identity-enroll', payload)
        self.assertEqual(result['issuers'][-1]['ref'], ref('new-issuer'))
        payload['transports'][0]['record']['method'] = 'oidc-session'
        payload['transports'][0] = self.proof(payload['transports'][0]['record'])
        with self.assertRaisesRegex(ContractError, 'identity_transport_method_unsupported'):
            self.call('identity-enroll', payload)

    def test_new_and_updated_membership_exact_revision(self):
        item = copy.deepcopy(self.state['memberships'][0])
        item['ref'] = ref('new-member')
        payload = {'authorityId': 'authority-one', 'record': item, 'previousRef': None}
        self.assertEqual(len(self.call('identity-membership-set', payload)['memberships']), 2)
        item['ref'] = {**ref('member'), 'revision': 2}
        payload['previousRef'] = ref('member')
        result = self.call('identity-membership-set', payload)
        self.assertEqual(result['memberships'][0]['ref']['revision'], 2)
        self.assertEqual(self.state, self.before)
        payload['previousRef']['revision'] = 0
        with self.assertRaisesRegex(ContractError, 'identity_previous_revision_mismatch'):
            self.call('identity-membership-set', payload)

    def test_revision_owner_and_active_reference_checks(self):
        item = copy.deepcopy(self.state['memberships'][0]); item['ref'] = ref('new-member')
        payload = {'authorityId': 'authority-one', 'record': item, 'previousRef': None}
        item['ref']['ownerHubId'] = 'other-hub'
        with self.assertRaisesRegex(ContractError, 'identity_reference_owner_mismatch'):
            self.call('identity-membership-set', payload)
        item['ref'] = {**ref('new-member'), 'revision': 2}
        with self.assertRaisesRegex(ContractError, 'identity_initial_revision_invalid'):
            self.call('identity-membership-set', payload)
        item['ref'] = ref('new-member'); item['identityRef'] = ref('missing')
        with self.assertRaisesRegex(ContractError, 'identity_reference_unavailable'):
            self.call('identity-membership-set', payload)

    def test_direct_grants_only(self):
        item = copy.deepcopy(self.state['grants'][0]); item['ref'] = ref('new-grant')
        payload = {'authorityId': 'authority-one', 'record': item, 'previousRef': None}
        self.assertEqual(len(self.call('identity-grant-set', payload)['grants']), 2)
        item['delegationRef'] = ref('delegation')
        with self.assertRaisesRegex(ContractError, 'delegation_not_supported'):
            self.call('identity-grant-set', payload)
        item['delegationRef'] = None; item['actorRef'] = ref('service')
        with self.assertRaisesRegex(ContractError, 'delegation_not_supported'):
            self.call('identity-grant-set', payload)

    def test_approval_references_must_exist_and_be_active(self):
        item = {'ref': ref('approval'), 'grantRef': ref('grant'), 'approverRef': ref('human'),
                'approverGrantRef': ref('grant'), 'payloadDigest': 'sha256:' + 'a' * 64,
                'audience': {'hubId': 'hub-one', 'serviceId': 'task-owner'},
                'operationId': 'operation-one', 'expectedVersion': 1, 'decision': 'approved',
                'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:10:00Z'}
        payload = {'authorityId': 'authority-one', 'record': item, 'previousRef': None}
        self.assertEqual(len(self.call('identity-approval-set', payload)['approvals']), 1)
        self.state['grants'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'identity_reference_unavailable'):
            self.call('identity-approval-set', payload)

    def test_revoke_retains_record_and_invalidates_old_reference(self):
        payload = {'authorityId': 'authority-one', 'targetRef': ref('human')}
        result = self.call('identity-revoke', payload)
        self.assertEqual(len(result['identities']), len(self.state['identities']))
        self.assertEqual(result['identities'][0]['status'], 'revoked')
        self.assertEqual(result['identities'][0]['ref']['revision'], 2)
        self.assertEqual(self.state, self.before)
        with self.assertRaisesRegex(ContractError, 'identity_reference_unavailable'):
            transition(result, 'identity-revoke', payload, hub_id='hub-one')
        self.state['identities'][0]['ref']['revision'] = 9007199254740991
        payload['targetRef']['revision'] = 9007199254740991
        with self.assertRaisesRegex(ContractError, 'identity_revision_exhausted'):
            self.call('identity-revoke', payload)

    def test_application_account_enrollment_and_atomic_rotation(self):
        payload = self.application_account()
        first = self.call('identity-application-account-set', payload)
        self.assertEqual(first['applicationAccounts'], [payload['record']])
        self.assertEqual({row['kind'] for row in first['secretReferences']},
                         {'nats-administrator-credential', 'nats-account-issuer'})
        rotated = copy.deepcopy(payload)
        rotated['previousRef'] = ref('application-account')
        rotated['record']['ref']['revision'] = 2
        for change in (rotated['administratorCredential'], rotated['accountIssuer']):
            change['previousRef'] = copy.deepcopy(change['record']['ref'])
            change['record']['ref']['revision'] = 2
        result = transition(first, 'identity-application-account-set', rotated, hub_id='hub-one')
        self.assertEqual(result['applicationAccounts'][0]['ref']['revision'], 2)
        self.assertEqual({row['ref']['revision'] for row in result['secretReferences']}, {2})
        self.assertEqual(len(result['secretReferences']), 2)

    def test_application_account_refuses_unbound_or_secret_input(self):
        for change, error in (
                (lambda p: p['record'].update(accountPublicKey=ACCOUNT[:-1] + 'A'), None),
                (lambda p: p['record'].update(profileId='other-profile'), 'application_account_secret_binding'),
                (lambda p: p['record']['scope'].update(projectId=None), 'application_account_scope_mismatch'),
                (lambda p: p['accountIssuer']['record'].update(ownerIdentityRef=ref('service')),
                 'application_account_secret_binding'),
                (lambda p: p['administratorCredential']['record'].update(kind='nats-account-issuer'),
                 'application_account_secret_binding')):
            with self.subTest(error=error):
                self.state = copy.deepcopy(self.before)
                payload = self.application_account(); change(payload)
                with self.assertRaises(ContractError) as raised:
                    self.call('identity-application-account-set', payload)
                if error is not None:
                    self.assertEqual(raised.exception.code, error)
        payload = self.application_account()
        payload['administratorCredential']['record']['secret'] = 'never-store-this'
        with self.assertRaises(ContractError):
            self.call('identity-application-account-set', payload)

    def test_application_account_refuses_revoked_administrator_issuer(self):
        payload = self.application_account()
        self.state['issuers'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'identity_reference_unavailable'):
            self.call('identity-application-account-set', payload)

    def test_closed_payload_and_unsupported_command(self):
        payload = self.enrollment(); payload['actor'] = 'admin'
        with self.assertRaises(ContractError):
            self.call('identity-enroll', payload)
        with self.assertRaisesRegex(ContractError, 'identity_transition_unsupported'):
            self.call('identity-delete', {})


if __name__ == '__main__':
    unittest.main()
