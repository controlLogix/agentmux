"""Offline bootstrap controls using real signatures and the shared ledger code.

The NATS responses are mocked; these tests do not qualify a live broker or the
private-profile provisioning ceremony.
"""
import copy
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from nats.js.api import StreamState
from nats.js.errors import APIError, NotFoundError
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from identity.bootstrap import BootstrapPermit, BootstrapOwner
from identity.test_authority import fixture, SEED


class MockNATS:
    """In-memory responses only; no production transport or authority assertion."""
    def __init__(self, config, created):
        self.config, self.created = config, created
        self.messages, self.publish_count = [], 0
        self.lose_ack = False

    async def stream_info(self, stream):
        return SimpleNamespace(config=self.config, created=self.created,
            state=StreamState(messages=len(self.messages), bytes=sum(len(m.data) for m in self.messages),
                first_seq=1 if self.messages else 0, last_seq=len(self.messages),
                num_deleted=0, consumer_count=0))

    async def get_msg(self, stream, *, subject=None, seq=None, direct=False):
        if not self.messages:
            raise NotFoundError()
        return self.messages[seq - 1 if seq else -1]

    async def publish(self, subject, data, *, headers):
        self.publish_count += 1
        if headers != {'Nats-Expected-Stream': 'IDENTITY',
                       'Nats-Expected-Last-Subject-Sequence': str(len(self.messages))}:
            raise APIError(err_code=10071)
        self.messages.append(SimpleNamespace(subject=subject, data=data, seq=len(self.messages) + 1))
        if self.lose_ack:
            self.lose_ack = False
            raise TimeoutError('private broker detail')
        return SimpleNamespace(stream='IDENTITY', seq=len(self.messages), duplicate=False)


def initial_record(now):
    record = fixture()[0]
    state, op = record['state'], record['operation']
    scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    for collection in ('memberships', 'grants'):
        for item in state[collection]:
            item['scope'] = copy.deepcopy(scope)
    for collection in ('issuers', 'transports', 'grants'):
        for item in state[collection]:
            item['issuedAt'] = (now - timedelta(seconds=5)).isoformat().replace('+00:00', 'Z')
            item['expiresAt'] = (now + timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')
    state['grants'][0].update(contractId='identity-enroll', resourceId='authority-one')
    op.update(scope=scope, expectedVersion=0, payloadDigest=payload_digest(state),
              deadline=(now + timedelta(minutes=4)).isoformat().replace('+00:00', 'Z'),
              taskId=None, runId=None, attemptId=None)
    record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None,
                  outcome='committed', recordedAt=now.isoformat().replace('+00:00', 'Z'))
    record['authorizationDecision'] = {'operationId': op['operationId'], 'decision': 'allowed',
        'reason': 'explicit_enrollment', 'actorRef': op['effectiveActorRef'], 'contractId': 'identity-bootstrap'}
    return record


class BootstrapTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.record = initial_record(self.now)
        self.policy = Retention(2_097_152, 262_144)
        binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
                               canonical_bytes(self.record['operation']['scope']))
        self.subject = owner_subject(binding)
        config = self.policy.stream_config(stream='IDENTITY', subject=self.subject)
        self.js = MockNATS(config, self.now)
        self.ledger = OwnerLedger(self.js, stream='IDENTITY', subject=self.subject,
            binding=binding, retention=self.policy, stream_identity=StreamIdentity(self.now, 0))

    def permit(self, **changes):
        args = dict(record=canonical_bytes(self.record), hub_id='hub-one', entity_id='authority-one',
                    profile_id='profile-one', organization_id='org-one',
                    issued_at=self.now - timedelta(seconds=1), expires_at=self.now + timedelta(minutes=4))
        args.update(changes)
        return BootstrapPermit(**args)

    def proofs(self):
        proofs = []
        for collection, seed in (('issuers', SEED), ('transports', bytes(reversed(SEED)))):
            for credential in self.record['state'][collection]:
                claims = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': 'profile-one',
                          'authorityId': 'authority-one', 'credential': credential}
                proofs.append({'ref': copy.deepcopy(credential['ref']), 'proof': sign_claims(claims, seed)})
        return proofs

    async def test_actual_ledger_append_and_exact_replay(self):
        permit = self.permit()
        owner = BootstrapOwner(self.ledger, permit)
        receipt = await owner.execute(self.proofs())
        self.assertEqual((receipt.sequence, receipt.replayed, self.js.publish_count), (1, False, 1))
        self.assertEqual(self.js.messages[0].data, permit.record)
        replay = await owner.execute(self.proofs())
        self.assertTrue(replay.replayed)
        self.assertEqual(self.js.publish_count, 1)
        self.assertNotIn('user-one', repr(permit))
        self.assertFalse(hasattr(receipt, 'record'))

    async def test_lost_ack_reconciles_without_new_operation_or_publish(self):
        owner = BootstrapOwner(self.ledger, self.permit())
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await owner.execute(self.proofs())
        result = await owner.execute(self.proofs())
        self.assertEqual(result.operation_id, self.record['operation']['operationId'])
        self.assertTrue(result.replayed)
        self.assertEqual(self.js.publish_count, 1)

    async def test_every_credential_proof_is_required_exactly_once(self):
        owner = BootstrapOwner(self.ledger, self.permit())
        proofs = self.proofs()
        for invalid in ([], proofs[:1], proofs + [proofs[0]], [proofs[0], proofs[0]]):
            with self.subTest(count=len(invalid)):
                with self.assertRaisesRegex(ContractError, 'bootstrap_proofs_incomplete'):
                    await owner.execute(invalid)
        self.assertEqual(self.js.publish_count, 0)

    async def test_wrong_signature_or_ref_cannot_choose_roots(self):
        owner = BootstrapOwner(self.ledger, self.permit())
        proofs = self.proofs()
        proofs[0]['proof'] = sign_claims({'different': True}, SEED)
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await owner.execute(proofs)
        proofs = self.proofs(); proofs[0]['ref']['id'] = 'unapproved'
        with self.assertRaisesRegex(ContractError, 'bootstrap_proofs_incomplete'):
            await owner.execute(proofs)
        self.assertEqual(self.js.publish_count, 0)

    async def test_record_and_permit_are_immutable(self):
        permit = self.permit()
        self.record['state']['identities'][0]['principalId'] = 'changed'
        self.assertNotEqual(strict_loads(permit.record)['state'], self.record['state'])
        with self.assertRaises(AttributeError):
            permit.record = b'{}'

    async def test_initial_record_pins_and_provenance_are_required(self):
        for field, value in [('hub_id', 'other-hub'), ('entity_id', 'other-entity'),
                             ('profile_id', 'other-profile'), ('organization_id', 'other-org')]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ContractError, 'bootstrap_owner_mismatch'):
                    self.permit(**{field: value})
        for field, value in [('entityVersion', 2), ('previousRevision', 1), ('outcome', 'rejected')]:
            changed = copy.deepcopy(self.record); changed[field] = value
            with self.assertRaisesRegex(ContractError, 'bootstrap_initial_record_invalid'):
                self.permit(record=canonical_bytes(changed))
        changed = copy.deepcopy(self.record); del changed['authorizationDecision']
        with self.assertRaisesRegex(ContractError, 'bootstrap_provenance_required'):
            self.permit(record=canonical_bytes(changed))
        changed = copy.deepcopy(self.record); changed['state']['identities'][0]['principalId'] = 'changed'
        with self.assertRaisesRegex(ContractError, 'bootstrap_initial_record_invalid'):
            self.permit(record=canonical_bytes(changed))

    async def test_malformed_record_times_are_fixed_errors(self):
        changed = copy.deepcopy(self.record)
        changed['recordedAt'] = '2026-99-99T00:00:00Z'
        with self.assertRaisesRegex(ContractError, 'credential_time_invalid'):
            self.permit(record=canonical_bytes(changed))

    async def test_short_permit_interval_and_expiry(self):
        with self.assertRaisesRegex(ContractError, 'bootstrap_permit_time_invalid'):
            self.permit(expires_at=self.now + timedelta(minutes=6))
        with self.assertRaisesRegex(ContractError, 'bootstrap_permit_time_invalid'):
            self.permit(issued_at=self.now.replace(tzinfo=None))
        expired = self.permit(issued_at=self.now - timedelta(minutes=2),
                              expires_at=self.now - timedelta(minutes=1))
        with self.assertRaisesRegex(ContractError, 'bootstrap_permit_expired'):
            await BootstrapOwner(self.ledger, expired).execute(self.proofs())
        self.assertEqual(self.js.publish_count, 0)

    async def test_different_existing_bootstrap_never_replaced(self):
        owner = BootstrapOwner(self.ledger, self.permit())
        await owner.execute(self.proofs())
        changed = copy.deepcopy(self.record); changed['recordId'] = 'different-record'
        self.js.messages[0].data = canonical_bytes(changed)
        with self.assertRaisesRegex(ContractError, 'bootstrap_operation_conflict'):
            await owner.execute(self.proofs())
        self.assertEqual(self.js.publish_count, 1)

    async def test_recreated_stream_is_not_an_empty_installation(self):
        self.js.created += timedelta(seconds=1)
        with self.assertRaisesRegex(ContractError, 'owner_recovery_required'):
            await BootstrapOwner(self.ledger, self.permit()).execute(self.proofs())
        self.assertEqual(self.js.publish_count, 0)


if __name__ == '__main__':
    unittest.main()
