"""Only the ordinary-secret use journal separates generation from sequence."""
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import CREATED, SCOPE, FakeJetStream, record


class OrdinarySecretTargetVersionTests(unittest.IsolatedAsyncioTestCase):
    def owner(self, domain='ordinary-secret-uses', kind='effect'):
        binding = OwnerBinding('hub-one', domain, 'use-one', kind, canonical_bytes(SCOPE))
        policy = Retention(2_097_152, 262_144)
        js = FakeJetStream(policy)
        js.config.subjects = [owner_subject(binding)]
        owner = OwnerLedger(js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        value = record()
        value.update(entityId=binding.entity_id, entityKind=kind, ownerDomain=domain, effects=[])
        value['operation']['expectedVersion'] = 1
        return owner, js, value

    async def test_immutable_generation_one_does_not_fake_ledger_sequence(self):
        owner, js, value = self.owner()
        with self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
            await owner.append(value, expected_sequence=0, completion_records=2)
        stored = await owner.append(value, expected_sequence=0,
            expected_target_version=1, completion_records=2)
        retained = strict_loads(stored.record)
        self.assertEqual((retained['entityVersion'], retained['previousRevision'],
                          retained['operation']['expectedVersion']), (1, 0, 1))
        replay = await owner.append(value, expected_sequence=0,
            expected_target_version=1, completion_records=2)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(js.messages), 1)

    async def test_no_other_domain_or_kind_gains_target_version_bypass(self):
        for domain, kind in (('ordinary-secret-uses-other', 'effect'),
                ('ordinary-secret-uses', 'task'), ('ordinary-secret-uses', 'attempt'),
                ('task', 'effect'), ('identity', 'effect')):
            owner, js, value = self.owner(domain, kind)
            with self.subTest(domain=domain, kind=kind), self.assertRaisesRegex(
                    ContractError, '^owner_target_version_invalid$'):
                await owner.append(value, expected_sequence=0,
                    expected_target_version=1, completion_records=2)
            self.assertFalse(js.messages)

    async def test_exact_pair_preserves_validation_budget_and_expiry(self):
        for target in (-1, True, 1.0, '1', 9_007_199_254_740_992):
            owner, js, value = self.owner()
            with self.subTest(target=target), self.assertRaisesRegex(
                    ContractError, '^owner_target_version_invalid$'):
                await owner.append(value, expected_sequence=0,
                    expected_target_version=target, completion_records=2)
            self.assertFalse(js.messages)
        owner, js, value = self.owner()
        with self.assertRaisesRegex(ContractError, '^owner_completion_budget_required$'):
            await owner.append(value, expected_sequence=0, expected_target_version=1)
        value['operation']['deadline'] = '2020-01-01T00:00:00Z'
        with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
            await owner.append(value, expected_sequence=0,
                expected_target_version=1, completion_records=2)
        self.assertFalse(js.messages)


if __name__ == '__main__':
    unittest.main()
