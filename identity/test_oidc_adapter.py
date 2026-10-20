"""External OIDC authentication and explicit identity-owner account linking."""
import base64
import copy
from datetime import datetime, timedelta
import unittest
from unittest.mock import AsyncMock, patch

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthoritySnapshot
from identity.commands import IdentityCommandOwner, prepare_change
from identity.oidc_adapter import (OIDCIdentityAdapter, OIDCProvider,
                                   OIDCLoginBinding, VerifiedOIDCIdentity,
                                   external_account_link_payload)
from identity.test_authority import NOW, SEED, fixture, ref
from identity.test_commands import command_fixture
from identity.transitions import transition
from state_owner.ledger import OwnerLedger, Snapshot, StoredRecord


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


_DEFAULT_TOKEN = object()


def link_command(payload):
    record, envelope = command_fixture()
    envelope.update(contractId='identity-external-account-link', payload=payload)
    envelope['operation'].update(payloadDigest=payload_digest(payload))
    record['state']['grants'][0].update(contractId='identity-external-account-link',
                                        resourceId='authority-one')
    claims = envelope['ingressAttestation']['claims']
    claims.update(contractId=envelope['contractId'], operation=copy.deepcopy(envelope['operation']))
    envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
    return record, envelope


class OIDCAdapterTests(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.provider = OIDCProvider('https://identity.example/realms/team', 'agentmux', 'key-one',
            encoded(bytes(self.key.verify_key)))
        self.adapter = OIDCIdentityAdapter(self.provider)
        self.login = self.adapter.begin_login(now=NOW)
        self.claims = {'iss': self.provider.issuer, 'sub': 'keycloak-user-184',
            'aud': self.provider.audience, 'iat': int(NOW.timestamp()),
            'exp': int((NOW + timedelta(minutes=4)).timestamp()), 'nonce': self.login.nonce,
            'email': 'mutable@example.test', 'name': 'Mutable Display Name'}

    def token(self, claims=None, header=None, key=None):
        header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'} if header is None else header
        claims = self.claims if claims is None else claims
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        signature = (key or self.key).sign('.'.join(parts).encode('ascii')).signature
        return '.'.join((*parts, encoded(signature)))

    def verify(self, token=_DEFAULT_TOKEN, login=None, **changes):
        login = login or self.login
        arguments = {'login': login, 'returned_state': login.state, 'now': NOW}
        arguments.update(changes)
        return self.adapter.verify(self.token() if token is _DEFAULT_TOKEN else token, **arguments)

    def fresh(self):
        login = self.adapter.begin_login(now=NOW)
        return login, {**self.claims, 'nonce': login.nonce}

    def test_exact_signed_identity_excludes_mutable_profile_claims(self):
        identity = self.verify()
        self.assertEqual(identity.external_identity,
            {'issuer': self.provider.issuer, 'subject': 'keycloak-user-184'})
        first = identity.external_identity
        first['subject'] = 'changed'
        self.assertEqual(identity.external_identity['subject'], 'keycloak-user-184')
        self.assertNotIn('keycloak-user-184', repr(identity))
        payload = external_account_link_payload(authority_id='authority-one',
            identity_ref=ref('human'), verified_identity=identity)
        self.assertEqual(set(payload), {'authorityId', 'identityRef', 'externalIdentity'})
        self.assertNotIn('email', canonical_bytes(payload).decode())
        with self.assertRaisesRegex(ContractError, 'oidc_identity_unverified'):
            external_account_link_payload(authority_id='authority-one', identity_ref=ref('human'),
                verified_identity=object())
        with self.assertRaisesRegex(ContractError, 'oidc_identity_unverified'):
            VerifiedOIDCIdentity(self.provider.issuer, 'forged', object())

    def test_login_binding_signature_and_key_are_exact(self):
        cases = ('state', 'unicode-state', 'nonce', 'unicode-nonce', 'key-id', 'algorithm',
                 'signature', 'malformed')
        for name in cases:
            login, claims = self.fresh()
            arguments, error = {}, 'oidc_identity_invalid'
            if name == 'state':
                token, arguments, error = self.token(claims=claims), {
                    'returned_state': 'x' * 43}, 'oidc_login_binding_invalid'
            elif name == 'unicode-state':
                token, arguments, error = self.token(claims=claims), {
                    'returned_state': 'é'}, 'oidc_login_binding_invalid'
            elif name == 'nonce':
                token = self.token(claims={**claims, 'nonce': 'x' * 43})
            elif name == 'unicode-nonce':
                token = self.token(claims={**claims, 'nonce': 'é'})
            elif name == 'key-id':
                token, error = self.token(claims=claims, header={
                    'alg': 'EdDSA', 'kid': 'other', 'typ': 'JWT'}), 'oidc_signing_key_mismatch'
            elif name == 'algorithm':
                token, error = self.token(claims=claims, header={
                    'alg': 'none', 'kid': 'key-one', 'typ': 'JWT'}), 'oidc_signing_key_mismatch'
            elif name == 'malformed':
                token, error = None, 'oidc_token_invalid'
            else:
                token, error = self.token(claims=claims, key=SigningKey.generate()), 'oidc_signature_invalid'
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, error):
                self.verify(token, login=login, **arguments)
            with self.assertRaisesRegex(ContractError, 'oidc_login_binding_invalid'):
                self.verify(self.token(claims=claims), login=login)

    def test_issuer_audience_time_and_subject_are_exact(self):
        changes = {
            'issuer': ('iss', 'https://other.example/realms/team', 'oidc_identity_invalid'),
            'audience': ('aud', 'other-client', 'oidc_audience_invalid'),
            'expired': ('exp', int(NOW.timestamp()), 'oidc_time_invalid'),
            'future': ('iat', int((NOW + timedelta(seconds=1)).timestamp()), 'oidc_time_invalid'),
            'long-lived': ('exp', int((NOW + timedelta(minutes=6)).timestamp()), 'oidc_time_invalid'),
            'subject': ('sub', '', 'oidc_identity_invalid'),
        }
        for name, (field, value, error) in changes.items():
            login, claims = self.fresh()
            claims[field] = value
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, error):
                self.verify(self.token(claims=claims), login=login)
        login, claims = self.fresh()
        claims.update(aud=['agentmux', 'account'], azp='agentmux')
        self.assertEqual(self.verify(self.token(claims=claims), login=login).external_identity['subject'],
                         self.claims['sub'])
        login, claims = self.fresh()
        claims.update(aud=['agentmux', 'account'], azp='account')
        with self.assertRaisesRegex(ContractError, 'oidc_audience_invalid'):
            self.verify(self.token(claims=claims), login=login)

    def test_provider_configuration_is_bounded_and_secret_free(self):
        self.assertNotIn(self.provider.public_key, repr(self.provider))
        self.assertEqual(repr(self.adapter), '<OIDCIdentityAdapter configured>')
        self.assertNotIn(self.login.state, repr(self.login))
        for arguments in (
                ('http://identity.example/realms/team', 'agentmux', 'key-one', self.provider.public_key),
                ('https://identity.example/realms/team/', 'agentmux', 'key-one', self.provider.public_key),
                (self.provider.issuer, 'agentmux', 'key-one', encoded(b'short'))):
            with self.assertRaisesRegex(ContractError, 'oidc_provider_invalid'):
                OIDCProvider(*arguments)
        with self.assertRaisesRegex(ContractError, 'oidc_login_binding_invalid'):
            OIDCLoginBinding(self.adapter, 's' * 43, 'n' * 43, NOW, object())

    def test_signing_key_rotation_requires_the_new_protected_pin(self):
        old_login, old_claims = self.fresh()
        old_token = self.token(claims=old_claims)
        new_key = SigningKey.generate()
        rotated = OIDCProvider(self.provider.issuer, self.provider.audience,
            'key-two', encoded(bytes(new_key.verify_key)))
        rotated_adapter = OIDCIdentityAdapter(rotated)
        new_login = rotated_adapter.begin_login(now=NOW)
        claims = {'iss': rotated.issuer, 'sub': 'keycloak-user-184',
            'aud': rotated.audience, 'iat': int(NOW.timestamp()),
            'exp': int((NOW + timedelta(minutes=4)).timestamp()),
            'nonce': new_login.nonce}
        header = {'alg': 'EdDSA', 'kid': 'key-two', 'typ': 'JWT'}
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        new_token = '.'.join((*parts, encoded(new_key.sign(
            '.'.join(parts).encode()).signature)))

        with self.assertRaisesRegex(ContractError, 'oidc_signing_key_mismatch'):
            self.adapter.verify(new_token, login=old_login,
                returned_state=old_login.state, now=NOW)
        with self.assertRaisesRegex(ContractError, 'oidc_signing_key_mismatch'):
            rotated_adapter.verify(old_token, login=new_login,
                returned_state=new_login.state, now=NOW)

        admitted = rotated_adapter.begin_login(now=NOW)
        claims['nonce'] = admitted.nonce
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        admitted_token = '.'.join((*parts, encoded(new_key.sign(
            '.'.join(parts).encode()).signature)))
        verified = rotated_adapter.verify(admitted_token, login=admitted,
            returned_state=admitted.state, now=NOW)
        self.assertEqual(verified.external_identity,
            {'issuer': self.provider.issuer, 'subject': 'keycloak-user-184'})


class ExternalAccountLinkTests(unittest.TestCase):
    external = {'issuer': 'https://identity.example/realms/team', 'subject': 'keycloak-user-184'}

    def payload(self):
        return {'authorityId': 'authority-one', 'identityRef': ref('human'),
                'externalIdentity': copy.deepcopy(self.external)}

    def test_link_preserves_identity_reference_membership_and_grants(self):
        record, _ = fixture()
        before = copy.deepcopy(record['state'])
        result = transition(record['state'], 'identity-external-account-link', self.payload(),
                            hub_id='hub-one')
        self.assertEqual(result['identities'][0]['externalIdentity'], self.external)
        self.assertEqual(result['identities'][0]['ref'], before['identities'][0]['ref'])
        self.assertEqual(result['memberships'], before['memberships'])
        self.assertEqual(result['grants'], before['grants'])
        self.assertIsNone(record['state']['identities'][0]['externalIdentity'])

    def test_relink_duplicate_nonhuman_and_payload_identity_are_refused(self):
        record, _ = fixture()
        state = transition(record['state'], 'identity-external-account-link', self.payload(),
                           hub_id='hub-one')
        with self.assertRaisesRegex(ContractError, 'identity_external_account_already_linked'):
            transition(state, 'identity-external-account-link', self.payload(), hub_id='hub-one')
        duplicate = copy.deepcopy(record['state'])
        duplicate['identities'][1]['externalIdentity'] = copy.deepcopy(self.external)
        with self.assertRaisesRegex(ContractError, 'authority_external_identity_ambiguous'):
            transition(duplicate, 'identity-external-account-link', self.payload(), hub_id='hub-one')
        nonhuman = self.payload()
        nonhuman['identityRef'] = ref('service')
        with self.assertRaisesRegex(ContractError, 'identity_external_account_human_required'):
            transition(record['state'], 'identity-external-account-link', nonhuman, hub_id='hub-one')
        forged = self.payload()
        forged['email'] = 'authority@example.test'
        with self.assertRaises(ContractError):
            transition(record['state'], 'identity-external-account-link', forged, hub_id='hub-one')

    def test_current_owner_grant_and_hard_denial_control_link(self):
        payload = self.payload()
        record, envelope = link_command(payload)
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                                  canonical_bytes(envelope), now=NOW)
        stored = strict_loads(proposal.record)
        self.assertEqual((proposal.decision, stored['authorizationDecision']['actorRef']),
                         ('allowed', ref('human')))
        self.assertEqual(stored['state']['identities'][0]['externalIdentity'], self.external)
        denied = copy.deepcopy(record['state']['grants'][0])
        denied.update(ref=ref('link-denial'), decision='denied')
        record['state']['grants'].append(denied)
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                                  canonical_bytes(envelope), now=NOW)
        self.assertEqual((proposal.decision, proposal.reason), ('denied', 'hard_denial'))
        self.assertIsNone(strict_loads(proposal.record)['state']['identities'][0]['externalIdentity'])


class ExternalAccountOwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_verified_pair_commits_through_current_identity_owner(self):
        key = SigningKey.generate()
        provider = OIDCProvider('https://identity.example/realms/team', 'agentmux', 'key-one',
                                encoded(bytes(key.verify_key)))
        adapter = OIDCIdentityAdapter(provider)
        login = adapter.begin_login(now=NOW)
        claims = {'iss': provider.issuer, 'sub': 'keycloak-user-184', 'aud': provider.audience,
            'iat': int(NOW.timestamp()), 'exp': int((NOW + timedelta(minutes=4)).timestamp()),
            'nonce': login.nonce, 'email': 'not-authority@example.test'}
        header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'}
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        token = '.'.join((*parts, encoded(key.sign('.'.join(parts).encode('ascii')).signature)))
        verified = adapter.verify(token, login=login, returned_state=login.state, now=NOW)
        payload = external_account_link_payload(authority_id='authority-one',
            identity_ref=ref('human'), verified_identity=verified)
        record, envelope = link_command(payload)

        ledger = object.__new__(OwnerLedger)
        ledger.current = AsyncMock(return_value=Snapshot((StoredRecord(canonical_bytes(record), 7),), 7))
        ledger.outcome = AsyncMock(return_value=None)
        committed = {}

        async def append(value, *, expected_sequence, valid_until, completion_records):
            committed.update(value)
            self.assertEqual((expected_sequence, completion_records), (7, 0))
            self.assertGreater(valid_until, NOW)
            return StoredRecord(canonical_bytes(value), 8)

        ledger.append = AsyncMock(side_effect=append)
        owner = IdentityCommandOwner(ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        with patch('identity.commands.datetime', wraps=datetime) as clock:
            clock.now.return_value = NOW
            receipt = await owner.execute(canonical_bytes(envelope))
        self.assertEqual((receipt.decision, receipt.sequence), ('allowed', 8))
        self.assertEqual(committed['state']['identities'][0]['externalIdentity'],
                         {'issuer': provider.issuer, 'subject': claims['sub']})
        self.assertNotIn('email', canonical_bytes(committed).decode())


if __name__ == '__main__':
    unittest.main()
