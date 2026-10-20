"""Protected identity-service ingress for explicit external account linking."""
import copy
from datetime import datetime
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import (ContractError, canonical_bytes, sign_claims,
                                strict_loads)

from identity.service import IdentityService, verify_receipt
from identity.test_authority import NOW, SEED, ref
from identity.test_commands import command_fixture
from state_owner.ledger import StreamIdentity
from state_owner.retention import Retention
from state_owner.test_ledger import CREATED, FakeJetStream


class _ClockMeta(type):
    def __instancecheck__(cls, value):
        return isinstance(value, datetime)


class _Clock(datetime, metaclass=_ClockMeta):
    @classmethod
    def now(cls, tz=None):
        return NOW


class ExternalAccountLinkServiceTests(unittest.IsolatedAsyncioTestCase):
    external = {'issuer': 'https://identity.example/realms/team',
                'subject': 'keycloak-user-184'}

    def setUp(self):
        self.record, envelope = command_fixture()
        self.record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[],
                           repository=None)
        organization = {'organizationId': 'org-one', 'projectId': None,
                        'workspaceId': None}
        self.record['operation'].update(scope=copy.deepcopy(organization), expectedVersion=0)
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(organization)
        state['grants'][0].update(contractId='identity-external-account-link',
            resourceId='authority-one', scope=copy.deepcopy(organization))
        self.payload = {'authorityId': 'authority-one', 'identityRef': ref('human'),
                        'externalIdentity': copy.deepcopy(self.external)}
        self.claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('grant'),
            'operationId': 'external-account-link-one', 'expectedVersion': 1,
            'contractId': 'identity-external-account-link', 'payload': self.payload,
            'approvalRefs': [], 'issuedAt': '2026-10-09T12:00:01Z',
            'expiresAt': '2026-10-09T12:00:30Z'}
        policy = Retention(2_097_152, 262_144)
        self.js = FakeJetStream(policy)
        connection = SimpleNamespace(jetstream=lambda: self.js)
        self.service = IdentityService(connection, stream='OWNER',
            stream_identity=StreamIdentity(CREATED, 1), retention=policy,
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED)
        subject = self.service.ledger._subject
        self.js.config = policy.stream_config(stream='OWNER', subject=subject)
        self.js.messages = [SimpleNamespace(subject=subject, seq=1,
            data=canonical_bytes(self.record))]
        for module in ('identity.ingress', 'identity.commands', 'identity.service',
                       'state_owner.ledger'):
            patch(module + '.datetime', _Clock).start()
        self.addCleanup(patch.stopall)

    def request(self, seed=bytes(reversed(SEED))):
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': self.claims,
                                'signature': sign_claims(self.claims, seed)})

    async def test_current_administrator_links_once_and_exact_replay_is_stable(self):
        authorize = AsyncMock(side_effect=AssertionError(
            'account linking must not require an already-linked terminal session'))
        self.service.ingress.require_terminal_sessions(authorize)
        raw = self.request()
        receipt = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['sequence'], receipt['replayed']),
                         ('allowed', 2, False))
        stored = strict_loads(self.js.messages[-1].data)
        identity = stored['state']['identities'][0]
        self.assertEqual((identity['ref'], identity['externalIdentity']),
                         (ref('human'), self.external))
        self.assertEqual(stored['state']['memberships'], self.record['state']['memberships'])
        self.assertEqual(stored['state']['grants'], self.record['state']['grants'])
        self.assertEqual(stored['authorizationDecision']['actorRef'], ref('human'))
        self.assertNotIn('email', canonical_bytes(stored).decode())

        replay = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((replay['decision'], replay['sequence'], replay['replayed']),
                         ('allowed', 2, True))
        self.assertEqual(len(self.js.messages), 2)

        self.claims.update(operationId='external-account-link-changed', expectedVersion=2)
        changed = self.request()
        refused = verify_receipt(await self.service.handle(changed), changed,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((refused['decision'], refused['reason']),
                         ('denied', 'identity_external_account_already_linked'))
        self.assertEqual(strict_loads(self.js.messages[-1].data)
                         ['state']['identities'][0]['externalIdentity'], self.external)
        authorize.assert_not_awaited()

    async def test_hard_denial_and_unauthenticated_request_never_link(self):
        denied = copy.deepcopy(self.record['state']['grants'][0])
        denied.update(ref=ref('external-link-denial'), decision='denied')
        self.record['state']['grants'].append(denied)
        self.js.messages[0].data = canonical_bytes(self.record)
        raw = self.request()
        receipt = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['reason']), ('denied', 'hard_denial'))
        self.assertIsNone(strict_loads(self.js.messages[-1].data)
                          ['state']['identities'][0]['externalIdentity'])

        original_count = len(self.js.messages)
        self.claims['operationId'] = 'external-account-link-forged'
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.service.handle(self.request(SEED))
        self.assertEqual(len(self.js.messages), original_count)

    async def test_project_scoped_exact_link_grant_refuses_before_mutation(self):
        project = {'organizationId': 'org-one', 'projectId': 'project-one',
                   'workspaceId': None}
        self.record['state']['memberships'][0]['scope'] = copy.deepcopy(project)
        self.record['state']['grants'][0].update(scope=copy.deepcopy(project),
            contractId='identity-external-account-link', resourceId='authority-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'identity_audit_scope_unavailable'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)
        self.assertIsNone(self.record['state']['identities'][0]['externalIdentity'])

    async def test_organization_wrong_grant_and_mutable_profile_input_refuse(self):
        self.record['state']['grants'][0].update(
            contractId='integration-effect-query', resourceId='effect-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        raw = self.request()
        receipt = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['reason']),
                         ('denied', 'grant_unavailable'))
        self.assertIsNone(strict_loads(self.js.messages[-1].data)
                          ['state']['identities'][0]['externalIdentity'])

        self.record['state']['grants'][0].update(
            contractId='identity-external-account-link', resourceId='authority-one')
        self.payload['email'] = 'mutable@example.test'
        self.claims['payload'] = self.payload
        self.claims['operationId'] = 'external-account-link-email'
        self.js.messages[0].data = canonical_bytes(self.record)
        self.js.messages = self.js.messages[:1]
        with self.assertRaises(ContractError):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)

    async def test_current_membership_and_grant_are_required(self):
        self.record['state']['memberships'][0]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        raw = self.request()
        receipt = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['reason']),
                         ('denied', 'membership_unavailable'))
        self.assertIsNone(strict_loads(self.js.messages[-1].data)
                          ['state']['identities'][0]['externalIdentity'])

    async def test_revoked_grant_refuses_before_mutation(self):
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims['operationId'] = 'external-account-link-revoked-grant'
        with self.assertRaisesRegex(ContractError, 'credential_grant_unavailable'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)


if __name__ == '__main__':
    unittest.main()
