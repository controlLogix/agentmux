"""Offline fault controls; real broker qualification is a separate required check."""
import asyncio
import copy
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from nats.js.api import StreamState
from nats.js.errors import APIError, NotFoundError

from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention


SCOPE = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
BINDING = OwnerBinding('hub-one', 'task', 'task-one', 'task', canonical_bytes(SCOPE))
SUBJECT = owner_subject(BINDING)
CREATED = datetime(2026, 10, 16, tzinfo=timezone.utc)


def record(operation='operation-one', version=1, previous=0):
    ref = {'id': 'ref-one', 'ownerHubId': 'hub-one', 'revision': 1}
    payload = {'id': operation}
    return {
        'schemaVersion': '1.0.0', 'recordId': 'record-' + operation,
        'entityId': 'task-one', 'entityKind': 'task', 'ownerHubId': 'hub-one',
        'ownerDomain': 'task', 'entityVersion': version, 'previousRevision': previous,
        'operation': {'schemaVersion': '1.0.0', 'operationId': operation,
                      'payloadDigest': payload_digest(payload), 'expectedVersion': version - 1,
                      'caller': {'principalId': 'user-one', 'kind': 'human', 'authenticatedIdentityRef': ref},
                      'effectiveActorRef': ref, 'scope': copy.deepcopy(SCOPE), 'taskId': 'task-one',
                      'runId': None, 'attemptId': None, 'delegationRef': None, 'grantRef': ref,
                      'approvalRefs': [], 'traceId': 'trace-one', 'causationId': 'cause-one',
                      'deadline': '2030-01-01T00:00:00Z', 'cancellationRef': ref},
        'recordedAt': '2026-10-16T00:00:00Z', 'outcome': 'committed',
        'state': {'status': 'blocked', 'originHubId': 'hub-origin', 'offerId': 'offer-one',
                  'reservationId': 'reservation-one'},
        'effects': [{'effectId': 'effect-' + operation, 'contractId': 'task-reserve',
                     'payloadDigest': payload_digest(payload), 'grantRef': ref,
                     'recovery': 'query-before-retry', 'payload': payload}],
        'artifacts': [], 'repository': None}


class FakeJetStream:
    """Only an offline boundary control, never evidence of broker atomicity."""
    def __init__(self, policy):
        self.config = policy.stream_config(stream='OWNER', subject=SUBJECT)
        self.messages = []
        self.deleted = 0
        self.lose_ack = False
        self.race = None
        self.created = CREATED

    async def stream_info(self, stream):
        state = StreamState(messages=len(self.messages), bytes=sum(len(m.data) for m in self.messages),
                            first_seq=1 if self.messages else 0, last_seq=len(self.messages),
                            num_deleted=self.deleted, consumer_count=0)
        return SimpleNamespace(config=self.config, state=state, created=self.created)

    async def get_msg(self, stream, *, subject=None, seq=None, direct=False):
        assert direct is False
        if not self.messages or (seq and seq > len(self.messages)):
            raise NotFoundError()
        return self.messages[seq - 1 if seq else -1]

    async def publish(self, subject, data, *, headers):
        assert headers['Nats-Expected-Stream'] == 'OWNER'
        if self.race:
            other, self.race = self.race, None
            self.messages.append(SimpleNamespace(subject=subject, data=canonical_bytes(other), seq=len(self.messages) + 1))
        if int(headers['Nats-Expected-Last-Subject-Sequence']) != len(self.messages):
            raise APIError(err_code=10071)
        self.messages.append(SimpleNamespace(subject=subject, data=data, seq=len(self.messages) + 1))
        if self.lose_ack:
            self.lose_ack = False
            raise TimeoutError('PRIVATE broker detail')
        return SimpleNamespace(stream='OWNER', seq=len(self.messages), duplicate=False)


class LedgerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = Retention(2_097_152, 262_144)
        self.js = FakeJetStream(self.policy)
        self.owner = self.new_owner()

    def new_owner(self):
        return OwnerLedger(self.js, stream='OWNER', subject=SUBJECT,
                           binding=BINDING, retention=self.policy,
                           stream_identity=StreamIdentity(CREATED, 0))

    async def test_complete_record_and_restart_replay_keep_original_outcome(self):
        first = record()
        stored = await self.owner.append(first, expected_sequence=0)
        self.assertEqual(strict_loads(stored.record), first)
        await self.owner.append(record('operation-two', 2, 1), expected_sequence=1)
        replay = await self.new_owner().append(first, expected_sequence=0)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.sequence, 1)
        self.assertEqual(len(self.js.messages), 2)
        self.assertEqual(strict_loads(replay.record)['state']['offerId'], 'offer-one')
        self.assertNotIn('offer-one', repr(replay))

    async def test_changed_content_reuse_is_rejected(self):
        first = record()
        await self.owner.append(first, expected_sequence=0)
        changed = copy.deepcopy(first)
        changed['operation']['payloadDigest'] = payload_digest({'other': True})
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.owner.append(changed, expected_sequence=0)
        self.assertEqual(len(self.js.messages), 1)

    async def test_lost_ack_reconciles_same_record_without_second_append(self):
        self.js.lose_ack = True
        first = record()
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.owner.append(first, expected_sequence=0)
        replay = await self.new_owner().outcome(first['operation']['operationId'], first['operation']['payloadDigest'])
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.js.messages), 1)

    async def test_racing_write_requires_reauthorization_no_automatic_retry(self):
        self.js.race = record('winner')
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await self.owner.append(record('loser'), expected_sequence=0)
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(strict_loads((await self.owner.current()).latest.record)['operation']['operationId'], 'winner')

    async def test_stale_proposal_does_not_commit(self):
        await self.owner.append(record(), expected_sequence=0)
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await self.owner.append(record('stale'), expected_sequence=0)

    async def test_gap_and_unsafe_retention_block_replay_and_admission(self):
        await self.owner.append(record(), expected_sequence=0)
        self.js.deleted = 1
        with self.assertRaisesRegex(ContractError, '^owner_history_gap$'):
            await self.owner.current()
        self.js.deleted = 0
        self.js.config.max_age = 30
        with self.assertRaisesRegex(ContractError, '^owner_retention_unsafe$'):
            await self.owner.current()

    async def test_malformed_owner_effect_and_size_never_publish(self):
        wrong = record()
        wrong['operation']['scope']['projectId'] = 'other-project'
        with self.assertRaisesRegex(ContractError, '^owner_binding_mismatch$'):
            await self.owner.append(wrong, expected_sequence=0)
        wrong = record()
        wrong['effects'][0]['payload']['id'] = 'changed'
        with self.assertRaisesRegex(ContractError, '^owner_effect_digest$'):
            await self.owner.append(wrong, expected_sequence=0)
        wrong = record()
        wrong['state']['body'] = 'x' * 65_536
        with self.assertRaisesRegex(ContractError, '^owner_record_size$'):
            await self.owner.append(wrong, expected_sequence=0)
        self.assertEqual(self.js.messages, [])

    async def test_deleted_suffix_is_not_an_empty_owner(self):
        async def missing(*args, **kwargs):
            raise NotFoundError()
        await self.owner.append(record(), expected_sequence=0)
        self.js.get_msg = missing
        with self.assertRaisesRegex(ContractError, '^owner_history_gap$'):
            await self.owner.current()

    async def test_rejected_outcome_preserves_state_and_no_effects(self):
        await self.owner.append(record(), expected_sequence=0)
        denied = record('denied', 2, 1)
        denied['outcome'] = 'rejected'
        denied['effects'] = []
        denied['operation']['expectedVersion'] = 0
        await self.owner.append(denied, expected_sequence=1)
        replay = await self.owner.outcome('denied', denied['operation']['payloadDigest'])
        self.assertEqual(strict_loads(replay.record)['outcome'], 'rejected')

    async def test_current_total_timeout_has_fixed_error(self):
        async def unavailable(*args, **kwargs):
            raise TimeoutError('PRIVATE')
        self.js.stream_info = unavailable
        with self.assertRaisesRegex(ContractError, '^owner_unavailable$'):
            await self.owner.current()

    async def test_subject_scope_cannot_disagree_with_bound_owner(self):
        with self.assertRaisesRegex(ContractError, '^owner_subject_mismatch$'):
            OwnerLedger(self.js, stream='OWNER', subject=SUBJECT.replace('org-one', 'other-org'),
                        binding=BINDING, retention=self.policy,
                        stream_identity=StreamIdentity(CREATED, 0))

    async def test_recreated_stream_and_empty_restore_require_reconciliation(self):
        await self.owner.append(record(), expected_sequence=0)
        self.js.messages.clear()
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.owner.current()
        restarted = OwnerLedger(self.js, stream='OWNER', subject=SUBJECT,
                                binding=BINDING, retention=self.policy,
                                stream_identity=StreamIdentity(CREATED, 1))
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await restarted.current()
        self.js.created += timedelta(seconds=1)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.new_owner().current()

    async def test_authorization_expiring_during_reads_refuses_publish(self):
        original = self.js.stream_info
        limit = datetime(2030, 1, 1, tzinfo=timezone.utc)
        calls = 0
        async def expiry_during_capacity_check(stream):
            nonlocal calls
            calls += 1
            return await original(stream)
        self.js.stream_info = expiry_during_capacity_check
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return limit if calls >= 3 else limit - timedelta(seconds=1)
        # A trusted decision existed before reads; the final capacity read reaches
        # its boundary. No sleep or relaxed deadline is needed for this check.
        with patch('state_owner.ledger.datetime', Clock):
            deadline = Clock(2030, 1, 1, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
                await self.owner.append(record(), expected_sequence=0, valid_until=deadline)
        self.assertEqual(self.js.messages, [])

    async def test_authorization_deadline_does_not_extend_command_deadline(self):
        expired = record()
        expired['operation']['deadline'] = '2020-01-01T00:00:00Z'
        with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
            await self.owner.append(expired, expected_sequence=0,
                                    valid_until=datetime(2040, 1, 1, tzinfo=timezone.utc))
        with self.assertRaisesRegex(ContractError, '^owner_authorization_deadline_invalid$'):
            await self.owner.append(record(), expected_sequence=0, valid_until=datetime(2030, 1, 1))
        self.assertEqual(self.js.messages, [])

    async def test_catalog_target_versions_remain_separate_from_catalog_sequence(self):
        binding = OwnerBinding('hub-one', 'definition', 'catalog-one', 'definition-catalog',
                               canonical_bytes(SCOPE))
        subject = owner_subject(binding)
        self.js.config.subjects = [subject]
        owner = OwnerLedger(self.js, stream='OWNER', subject=subject, binding=binding,
                            retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        def change(op, sequence, target_version, definitions):
            proposal = record(op, sequence + 1, sequence)
            proposal.update(entityId='catalog-one', entityKind='definition-catalog',
                            ownerDomain='definition', state={'definitions': definitions}, effects=[])
            proposal['operation']['expectedVersion'] = target_version
            proposal['operation']['taskId'] = None
            return proposal
        first = change('create-a', 0, 0, {'a': {'version': 1}})
        await owner.append(first, expected_sequence=0, expected_target_version=0)
        second = change('create-b', 1, 0, {'a': {'version': 1}, 'b': {'version': 1}})
        with self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
            await owner.append(second, expected_sequence=1)
        created = await owner.append(second, expected_sequence=1, expected_target_version=0)
        self.assertEqual(strict_loads(created.record)['operation']['expectedVersion'], 0)
        stale = change('update-a', 2, 0, {'a': {'version': 2}, 'b': {'version': 1}})
        with self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
            await owner.append(stale, expected_sequence=2, expected_target_version=1)
        self.assertEqual(len(self.js.messages), 2)
        stale['operation']['expectedVersion'] = 1
        await owner.append(stale, expected_sequence=2, expected_target_version=1)
        self.assertEqual(len(self.js.messages), 3)

    async def test_target_version_argument_cannot_weaken_task_version_check(self):
        with self.assertRaisesRegex(ContractError, '^owner_target_version_invalid$'):
            await self.owner.append(record(), expected_sequence=0, expected_target_version=0)


class BoardOperationTargetVersionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = Retention(2_097_152, 262_144)
        self.binding = OwnerBinding('hub-one', 'federation-board-operations',
                                    'board-one', 'attempt', canonical_bytes(SCOPE))
        self.js = FakeJetStream(self.policy)
        self.js.config.subjects = [owner_subject(self.binding)]
        self.owner = self.new_owner()

    def new_owner(self):
        return OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding),
                           binding=self.binding, retention=self.policy,
                           stream_identity=StreamIdentity(CREATED, 0),
                           require_completion_budget=True)

    def proposal(self, operation='claim-one', sequence=0, card_version=41):
        value = record(operation, sequence + 1, sequence)
        value.update(entityId=self.binding.entity_id, entityKind=self.binding.entity_kind,
                     ownerDomain=self.binding.owner_domain, state={'cardId': 'card-one'}, effects=[])
        value['operation']['expectedVersion'] = card_version
        return value

    async def test_card_target_version_is_separate_from_journal_sequence(self):
        first = self.proposal()
        for options in ({}, {'expected_target_version': 40}):
            with self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
                await self.owner.append(first, expected_sequence=0, completion_records=0, **options)
        stored = await self.owner.append(first, expected_sequence=0,
                                         expected_target_version=41, completion_records=0)
        second = self.proposal('claim-two', 1, 73)
        next_stored = await self.owner.append(second, expected_sequence=1,
                                              expected_target_version=73, completion_records=0)
        self.assertEqual((stored.sequence, next_stored.sequence), (1, 2))
        self.assertEqual(strict_loads(next_stored.record)['entityVersion'], 2)
        self.assertEqual(strict_loads(next_stored.record)['operation']['expectedVersion'], 73)

    async def test_board_target_version_requires_exact_domain_and_kind(self):
        bindings = [(domain, 'attempt') for domain in
                    ('task', 'integration', 'federation-board', 'federation-board-operations-other')]
        bindings += [('federation-board-operations', kind) for kind in
                     ('task', 'delegation', 'effect', 'approval', 'project', 'plugin-instance',
                      'plugin-storage', 'identity-authority', 'configuration')]
        for domain, kind in bindings:
            with self.subTest(domain=domain, kind=kind):
                self.binding = OwnerBinding('hub-one', domain, 'board-one', kind, canonical_bytes(SCOPE))
                self.js.config.subjects = [owner_subject(self.binding)]
                with self.assertRaisesRegex(ContractError, '^owner_target_version_invalid$'):
                    await self.new_owner().append(self.proposal(), expected_sequence=0,
                                                  expected_target_version=41, completion_records=0)
        self.assertEqual(self.js.messages, [])

    async def test_board_target_version_retains_validation_and_completion_checks(self):
        for target in (-1, True, 1.0, '41', 9_007_199_254_740_992):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ContractError, '^owner_target_version_invalid$'):
                    await self.owner.append(self.proposal(), expected_sequence=0,
                                            expected_target_version=target, completion_records=0)
        with self.assertRaisesRegex(ContractError, '^owner_completion_budget_required$'):
            await self.owner.append(self.proposal(), expected_sequence=0, expected_target_version=41)
        with self.assertRaisesRegex(ContractError, '^owner_completion_budget_invalid$'):
            await self.owner.append(self.proposal(), expected_sequence=0,
                                    expected_target_version=41, completion_records=-1)
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await self.owner.append(self.proposal(), expected_sequence=1,
                                    expected_target_version=41, completion_records=0)
        expired = self.proposal()
        expired['operation']['deadline'] = '2020-01-01T00:00:00Z'
        with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
            await self.owner.append(expired, expected_sequence=0,
                                    expected_target_version=41, completion_records=0)
        self.js.config.max_age = 30
        with self.assertRaisesRegex(ContractError, '^owner_retention_unsafe$'):
            await self.owner.append(self.proposal(), expected_sequence=0,
                                    expected_target_version=41, completion_records=0)
        self.assertEqual(self.js.messages, [])

    async def test_board_lost_ack_replay_keeps_original_target_and_record(self):
        first = self.proposal()
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.owner.append(first, expected_sequence=0,
                                    expected_target_version=41, completion_records=0)
        await self.new_owner().append(self.proposal('claim-two', 1, 73), expected_sequence=1,
                                      expected_target_version=73, completion_records=0)
        replay = await self.new_owner().append(first, expected_sequence=0, expected_target_version=41)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.sequence, 1)
        self.assertEqual(replay.record, canonical_bytes(first))
        changed = copy.deepcopy(first)
        changed['operation']['payloadDigest'] = payload_digest({'changed': True})
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.new_owner().append(changed, expected_sequence=0, expected_target_version=41)
        self.assertEqual(len(self.js.messages), 2)


if __name__ == '__main__':
    unittest.main()
