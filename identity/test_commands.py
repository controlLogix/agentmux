"""Identity transitions and audit preparation, without a live broker."""
import copy
from datetime import datetime, timedelta
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthoritySnapshot
from identity.commands import IdentityCommandOwner, prepare_change
from identity.test_authority import fixture, ref, SEED, NOW
from state_owner.ledger import OwnerLedger, StoredRecord, Snapshot


def command_fixture():
    record, env = fixture()
    record.update(effects=[], artifacts=[], repository=None)
    scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    record['state']['memberships'][0]['scope'] = copy.deepcopy(scope)
    record['state']['grants'][0].update(scope=copy.deepcopy(scope), contractId='identity-revoke', resourceId='authority-one')
    env.update(contractId='identity-revoke', destinationServiceId='identity-owner',
               payload={'authorityId': 'authority-one', 'targetRef': ref('transport')})
    env['operation'].update(scope=scope, expectedVersion=record['entityVersion'],
                            payloadDigest=payload_digest(env['payload']))
    claims = env['ingressAttestation']['claims']
    claims.update(contractId=env['contractId'], operation=copy.deepcopy(env['operation']),
                  audience={'hubId': 'hub-one', 'serviceId': 'identity-owner'})
    env['ingressAttestation']['signature'] = sign_claims(claims, SEED)
    return record, env


class CommandTests(unittest.TestCase):
    def test_external_obligations_cannot_claim_zero_completion_budget(self):
        for field, value in (('effects', [{'id': 'retained-effect'}]),
                             ('artifacts', [{'id': 'retained-artifact'}]),
                             ('repository', {'id': 'retained-repository'})):
            record, env = command_fixture()
            record[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                    ContractError, 'identity_external_obligation_unavailable'):
                prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                               canonical_bytes(env), now=NOW)

    def test_future_hard_denial_bounds_commit_time(self):
        record, env = command_fixture()
        deny = copy.deepcopy(record['state']['grants'][0])
        activation = NOW + timedelta(seconds=1)
        deny.update(ref=ref('future-denial'), decision='denied',
                    issuedAt=activation.isoformat().replace('+00:00', 'Z'))
        record['state']['grants'].append(deny)
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                                  canonical_bytes(env), now=NOW)
        self.assertEqual(proposal.decision, 'allowed')
        self.assertEqual(proposal.valid_until, activation)
        from identity.authority import evaluate_snapshot
        evaluated = evaluate_snapshot(AuthoritySnapshot(canonical_bytes(record), 7),
            canonical_bytes(env), audience={'hubId': 'hub-one', 'serviceId': 'identity-owner'}, now=NOW)
        self.assertEqual(evaluated.valid_until, activation)
        later = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                               canonical_bytes(env), now=activation)
        self.assertEqual((later.decision, later.reason), ('denied', 'hard_denial'))

    def test_complete_revocation_and_audit_share_record(self):
        record, env = command_fixture()
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), canonical_bytes(env), now=NOW)
        after = strict_loads(proposal.record)
        self.assertEqual(after['state']['transports'][0]['status'], 'revoked')
        self.assertEqual(after['state']['transports'][0]['ref']['revision'], 2)
        self.assertEqual(after['authorizationDecision']['decision'], 'allowed')
        self.assertEqual(after['previousRevision'], 7)
        self.assertEqual(after['entityVersion'], record['entityVersion'] + 1)
        self.assertEqual(record['state']['transports'][0]['status'], 'active')

    def test_denial_and_review_audit_do_not_change_grants(self):
        for decision in ('denied', 'review-required'):
            record, env = command_fixture()
            record['state']['grants'][0]['decision'] = decision
            after = strict_loads(prepare_change(AuthoritySnapshot(canonical_bytes(record), 7),
                                                canonical_bytes(env), now=NOW).record)
            self.assertEqual(after['outcome'], 'rejected')
            self.assertEqual(after['authorizationDecision']['decision'], decision)
            self.assertEqual(after['state']['transports'], record['state']['transports'])
            self.assertEqual(after['effects'], [])

    def test_project_admin_cannot_revoke_organization_identity(self):
        record, env = command_fixture()
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        for collection in ('memberships', 'grants'):
            record['state'][collection][0]['scope'] = copy.deepcopy(scope)
        env['operation']['scope'] = scope
        env['ingressAttestation']['claims']['operation'] = copy.deepcopy(env['operation'])
        env['ingressAttestation']['signature'] = sign_claims(env['ingressAttestation']['claims'], SEED)
        original = canonical_bytes(env)
        with self.assertRaisesRegex(ContractError, 'identity_audit_scope_unavailable'):
            prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), original, now=NOW)
        self.assertEqual(canonical_bytes(env), original)


    def test_organization_admin_cannot_mint_other_organization_grant(self):
        record, env = command_fixture()
        new_grant = copy.deepcopy(record['state']['grants'][0])
        new_grant.update(ref=ref('other-grant'), contractId='task-inspect', resourceId='task-one')
        new_grant['scope']['organizationId'] = 'other-org'
        env.update(contractId='identity-grant-set', payload={'authorityId': 'authority-one',
                   'record': new_grant, 'previousRef': None})
        record['state']['grants'][0]['contractId'] = 'identity-grant-set'
        env['operation']['payloadDigest'] = payload_digest(env['payload'])
        claims = env['ingressAttestation']['claims']
        claims.update(contractId=env['contractId'], operation=copy.deepcopy(env['operation']))
        env['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), canonical_bytes(env), now=NOW)
        self.assertEqual((proposal.decision, proposal.reason), ('denied', 'authority_organization_mismatch'))
        self.assertEqual(len(strict_loads(proposal.record)['state']['grants']), 1)

    def test_organization_admin_cannot_add_other_organization_membership(self):
        record, env = command_fixture()
        member = copy.deepcopy(record['state']['memberships'][0])
        member['ref'] = ref('other-member')
        member['scope']['organizationId'] = 'other-org'
        env.update(contractId='identity-membership-set', payload={'authorityId': 'authority-one',
                   'record': member, 'previousRef': None})
        record['state']['grants'][0]['contractId'] = 'identity-membership-set'
        env['operation']['payloadDigest'] = payload_digest(env['payload'])
        claims = env['ingressAttestation']['claims']
        claims.update(contractId=env['contractId'], operation=copy.deepcopy(env['operation']))
        env['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        proposal = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), canonical_bytes(env), now=NOW)
        self.assertEqual(proposal.reason, 'authority_organization_mismatch')
        self.assertEqual(len(strict_loads(proposal.record)['state']['memberships']), 1)


class CommandOwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_ledger_never_bootstraps(self):
        ledger = object.__new__(OwnerLedger)
        ledger.current = AsyncMock(return_value=Snapshot((), 0))
        owner = IdentityCommandOwner(ledger, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        _, env = command_fixture()
        with self.assertRaisesRegex(ContractError, 'identity_not_enrolled'):
            await owner.execute(canonical_bytes(env))

    async def test_shared_append_receives_one_complete_record(self):
        record, env = command_fixture()
        stored = StoredRecord(canonical_bytes(record), 7)
        ledger = object.__new__(OwnerLedger)
        ledger.current = AsyncMock(return_value=Snapshot((stored,), 7))
        ledger.outcome = AsyncMock(return_value=None)
        async def append(record, *, expected_sequence, valid_until, completion_records):
            self.assertEqual(completion_records, 0)
            self.assertEqual(expected_sequence, 7)
            self.assertGreater(valid_until, NOW)
            self.assertEqual(record['authorizationDecision']['decision'], 'allowed')
            return StoredRecord(canonical_bytes(record), 8)
        ledger.append = AsyncMock(side_effect=append)
        owner = IdentityCommandOwner(ledger, hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        with patch('identity.commands.datetime', wraps=datetime) as clock:
            clock.now.return_value = NOW
            result = await owner.execute(canonical_bytes(env))
        self.assertEqual((result.decision, result.sequence), ('allowed', 8))
        self.assertFalse(hasattr(result, 'record'))
        ledger.append.assert_awaited_once()
