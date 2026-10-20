"""Actual signatures with public test keys; no live credential enrollment claim."""
import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.authority import AuthorityReader
from identity.ingress import EnrolledIngress
from identity.test_authority import fixture, ref, SEED, NOW


class IngressTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record, _ = fixture()
        self.js = SimpleNamespace(get_msg=AsyncMock())
        self.reader = AuthorityReader(self.js, stream='IDENTITY', subject='identity.profile-one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'), signing_seed=SEED)
        self.claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref('grant'),
            'operationId': 'operation-one', 'expectedVersion': 1, 'contractId': 'task-inspect',
            'payload': {'taskId': 'task-one'}, 'approvalRefs': [],
            'issuedAt': '2026-10-09T12:00:01Z', 'expiresAt': '2026-10-09T12:00:30Z'}
        self.clock = patch('identity.ingress.datetime', wraps=datetime).start()
        self.addCleanup(patch.stopall)
        self.clock.now.return_value = NOW

    async def admit(self, seed=bytes(reversed(SEED))):
        self.js.get_msg.return_value = SimpleNamespace(subject='identity.profile-one', seq=1,
                                                       data=canonical_bytes(self.record))
        request = {'schemaVersion': '1.0.0', 'claims': self.claims,
                   'signature': sign_claims(self.claims, seed)}
        return await self.ingress.admit(canonical_bytes(request), cancellation_ref=ref('cancel'))

    async def test_exact_replay_keeps_operation_when_authority_window_changes(self):
        first = strict_loads((await self.admit()).envelope)
        shorter = NOW + timedelta(seconds=5)
        self.record['state']['grants'][0]['expiresAt'] = shorter.isoformat().replace('+00:00', 'Z')
        self.clock.now.return_value = NOW + timedelta(seconds=1)
        admitted = await self.admit()
        second = strict_loads(admitted.envelope)
        self.assertEqual(first['operation'], second['operation'])
        self.assertEqual(second['operation']['deadline'], self.claims['expiresAt'])
        self.assertNotEqual(first['messageId'], second['messageId'])
        self.assertEqual(admitted.decision.valid_until, shorter)
        self.assertEqual(datetime.fromisoformat(second['ingressAttestation']['claims']['expiresAt']), shorter)
        self.record['state']['grants'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'credential_grant_unavailable'):
            await self.admit()

    async def test_actor_and_scope_are_derived_and_payload_is_signed(self):
        result = await self.admit()
        envelope = strict_loads(result.envelope)
        self.assertEqual(result.decision.outcome, 'allowed')
        self.assertEqual(envelope['operation']['caller']['principalId'], 'user-one')
        self.assertEqual(envelope['operation']['scope'], self.record['state']['grants'][0]['scope'])
        self.assertEqual(envelope['payload'], {'taskId': 'task-one'})
        self.assertEqual(envelope['destinationServiceId'], 'task-owner')
        self.assertNotIn('user-one', repr(result))

    async def test_terminal_session_is_checked_against_derived_actor_and_scope(self):
        authorize = AsyncMock()
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'),
            signing_seed=SEED, session_authorizer=authorize)
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_session_required'):
            await self.admit()
        session_id = 'oidc_session_' + 'a' * 32
        self.claims['terminalSessionId'] = session_id
        admitted = await self.admit()
        operation = strict_loads(admitted.envelope)['operation']
        authorize.assert_awaited_once_with(session_id,
            operation['effectiveActorRef'], operation['scope'])

    async def test_terminal_lifecycle_contracts_are_signed_owner_login_exceptions(self):
        authorize = AsyncMock()
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'),
            signing_seed=SEED, session_authorizer=authorize)
        grant = self.record['state']['grants'][0]
        grant.update(resourceId='authority-one', decision='allowed')
        self.claims['expectedVersion'] = 0
        cases = (
            ('oidc-terminal-session-open', {}),
            ('oidc-terminal-session-status', {'attemptId': 'oidc_attempt_' + 'a' * 32}),
            ('oidc-terminal-session-close', {'sessionId': 'oidc_session_' + 'b' * 32}),
        )
        for contract, payload in cases:
            with self.subTest(contract=contract):
                grant['contractId'] = contract
                self.claims.update(contractId=contract, payload=payload,
                                   operationId='operation-' + contract)
                admitted = await self.admit()
                self.assertEqual(admitted.decision.outcome, 'allowed')
                self.assertEqual(strict_loads(admitted.envelope)['destinationServiceId'],
                                 'identity-owner')
        authorize.assert_not_awaited()

    async def test_protected_identity_revocation_does_not_depend_on_terminal_session(self):
        authorize = AsyncMock()
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'),
            signing_seed=SEED, session_authorizer=authorize)
        grant = self.record['state']['grants'][0]
        admin_scope = {'organizationId': 'org-one', 'projectId': None,
                       'workspaceId': None}
        self.record['state']['memberships'][0]['scope'] = admin_scope
        grant.update(resourceId='authority-one', contractId='identity-revoke',
                     decision='allowed', scope=admin_scope)
        self.claims.update(contractId='identity-revoke', expectedVersion=1,
            payload={'authorityId': 'authority-one', 'targetRef': ref('grant')})
        admitted = await self.admit()
        self.assertEqual(admitted.decision.outcome, 'allowed')
        self.assertEqual(strict_loads(admitted.envelope)['destinationServiceId'],
                         'identity-owner')
        authorize.assert_not_awaited()

    async def test_application_grant_cannot_use_identity_revocation_exemption(self):
        authorize = AsyncMock()
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'),
            signing_seed=SEED, session_authorizer=authorize)
        self.claims.update(contractId='identity-revoke',
            payload={'authorityId': 'authority-one', 'targetRef': ref('grant')})
        admitted = await self.admit()
        self.assertNotEqual(admitted.decision.outcome, 'allowed')
        self.assertIsNone(admitted.envelope)
        authorize.assert_not_awaited()

    async def test_terminal_open_refuses_caller_selected_identity_and_scope(self):
        grant = self.record['state']['grants'][0]
        grant.update(resourceId='authority-one', contractId='oidc-terminal-session-open',
                     decision='allowed')
        self.claims.update(expectedVersion=0, contractId='oidc-terminal-session-open',
                           operationId='operation-terminal-open', payload={})
        for key, value in (
                ('actor', 'forged-user'),
                ('scope', {'organizationId': 'org-one', 'projectId': 'other-project',
                           'workspaceId': None}),
                ('provider', 'other-provider'),
                ('projectId', 'other-project')):
            with self.subTest(key=key):
                self.claims['payload'] = {key: value}
                with self.assertRaises(ContractError):
                    await self.admit()

    async def test_forged_actor_scope_and_credential_are_rejected(self):
        for key, value in [('actor', 'admin'), ('scope', {'projectId': 'other'})]:
            self.claims[key] = value
            with self.assertRaises(ContractError): await self.admit()
            del self.claims[key]
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.admit(SEED)

    async def test_wrong_profile_expiry_and_revocation(self):
        self.claims['profileId'] = 'other-profile'
        with self.assertRaisesRegex(ContractError, 'credential_profile_mismatch'): await self.admit()
        self.claims['profileId'] = 'profile-one'
        self.clock.now.return_value = NOW + timedelta(minutes=1)
        with self.assertRaisesRegex(ContractError, 'credential_time_invalid'): await self.admit()
        self.clock.now.return_value = NOW
        self.record['state']['transports'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'credential_unavailable'): await self.admit()

    async def test_review_and_denial_never_return_a_dispatchable_envelope(self):
        for outcome in ('denied', 'review-required'):
            self.record['state']['grants'][0]['decision'] = outcome
            result = await self.admit()
            self.assertEqual(result.decision.outcome, outcome)
            self.assertIsNone(result.envelope)

    async def test_unenrolled_signer_and_oversized_body_fail(self):
        self.ingress = EnrolledIngress(self.reader, issuer_ref=ref('issuer'), signing_seed=bytes(reversed(SEED)))
        with self.assertRaisesRegex(ContractError, 'signature_invalid'): await self.admit()
        with self.assertRaisesRegex(ContractError, 'owner_body_limit'):
            await self.ingress.admit(b'x' * 65537, cancellation_ref=ref('cancel'))

    async def test_reservation_context_cannot_be_attached_to_inspect(self):
        self.js.get_msg.return_value = SimpleNamespace(subject='identity.profile-one', seq=1,
                                                       data=canonical_bytes(self.record))
        request = canonical_bytes({'schemaVersion':'1.0.0','claims':self.claims,
            'signature':sign_claims(self.claims,bytes(reversed(SEED)))})
        with self.assertRaisesRegex(ContractError,'task_reservation_preparation_required'):
            await self.ingress.admit(request,cancellation_ref=ref('cancel'),reservation_context={})
