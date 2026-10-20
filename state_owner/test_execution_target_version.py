"""Execution intent compatibility through the actual signed plan and B caller.

The existing fake broker controls storage failures only. These tests do not
qualify physical containers or claim broker atomicity.
"""
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from execution_owner import test_container as container_support
from execution_owner.container import RetainedContainerIntent
from state_owner.ledger import MAX_SEQUENCE, OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream


class ExecutionIntentVersionTests(container_support.ContainerTests):
    async def retained_original(self):
        # Exercise B's real construction path, including A's signed reservation,
        # enrollment and current admission. No engine command is needed.
        admission, intent = await self.authorized()
        stored = await intent.check()
        return admission, strict_loads(stored.record)

    def fresh_ledger(self, binding=None):
        binding = binding or self.intent_ledger._binding
        self.intent_js = FakeJetStream(self.policy)
        self.intent_js.config.subjects = [owner_subject(binding)]
        return self.reopen(binding)

    def reopen(self, binding=None):
        binding = binding or self.intent_ledger._binding
        return OwnerLedger(self.intent_js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)

    async def test_actual_signed_original_and_retained_caller_keep_executor_version(self):
        admission, proposal = await self.retained_original()
        binding = strict_loads(admission.binding)
        self.assertEqual(proposal['operation'], strict_loads(self.start())['operation'])
        self.assertEqual(proposal['operation'], binding['originalOperation'])
        self.assertEqual(proposal['operation']['expectedVersion'], 1)
        self.assertEqual((proposal['previousRevision'], proposal['entityVersion']), (0, 1))
        self.assertEqual(proposal['state']['executionBinding'], binding)
        self.assertEqual(proposal['effects'][0]['payloadDigest'], payload_digest(binding))
        stored = await RetainedContainerIntent(self.reopen(), admission.binding).check()
        self.assertEqual(stored.record, canonical_bytes(proposal))
        self.assertEqual(stored.sequence, 1)
        self.assertFalse(self.commands)

    async def test_execution_override_requires_exact_domain_and_kind(self):
        _, original = await self.retained_original()
        pairs = [('execution-other', 'attempt'), ('task', 'attempt'), ('integration', 'attempt')]
        pairs += [('execution', kind) for kind in ('task', 'effect', 'approval', 'configuration')]
        for domain, kind in pairs:
            with self.subTest(domain=domain, kind=kind):
                old = self.intent_ledger._binding
                binding = OwnerBinding(old.hub_id, domain, old.entity_id, kind, old.scope)
                ledger = self.fresh_ledger(binding)
                proposal = copy.deepcopy(original)
                proposal.update(ownerDomain=domain, entityKind=kind)
                with self.assertRaisesRegex(ContractError, '^owner_target_version_invalid$'):
                    await ledger.append(proposal, expected_sequence=0,
                        expected_target_version=1, completion_records=0)
                self.assertFalse(self.intent_js.messages)

    async def test_target_version_bounds_and_exact_original_version(self):
        _, proposal = await self.retained_original()
        ledger = self.fresh_ledger()
        for target in (-1, True, 1.0, '1', MAX_SEQUENCE + 1):
            with self.subTest(target=target), self.assertRaisesRegex(
                    ContractError, '^owner_target_version_invalid$'):
                await ledger.append(proposal, expected_sequence=0,
                    expected_target_version=target, completion_records=0)
        for target in (None, 0, 2):
            with self.subTest(target=target), self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
                await ledger.append(proposal, expected_sequence=0,
                    expected_target_version=target, completion_records=0)
        self.assertFalse(self.intent_js.messages)

    async def test_binding_and_scope_substitution_refuse_before_publish(self):
        _, original = await self.retained_original()
        ledger = self.fresh_ledger()
        for field, changed in (('entityId', 'another-run'), ('ownerHubId', 'another-hub'),
                ('ownerDomain', 'another-domain'), ('entityKind', 'effect')):
            proposal = copy.deepcopy(original)
            proposal[field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(ContractError, '^owner_binding_mismatch$'):
                await ledger.append(proposal, expected_sequence=0,
                    expected_target_version=1, completion_records=0)
        proposal = copy.deepcopy(original)
        proposal['operation']['scope']['projectId'] = 'another-project'
        with self.assertRaisesRegex(ContractError, '^owner_binding_mismatch$'):
            await ledger.append(proposal, expected_sequence=0,
                expected_target_version=1, completion_records=0)
        self.assertFalse(self.intent_js.messages)

    async def test_sequence_and_record_revision_guards_remain_separate(self):
        _, original = await self.retained_original()
        ledger = self.fresh_ledger()
        for sequence in (-1, True, 1.0, MAX_SEQUENCE + 1):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
                await ledger.append(original, expected_sequence=sequence,
                    expected_target_version=1, completion_records=0)
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await ledger.append(original, expected_sequence=1, expected_target_version=1, completion_records=0)
        for field, value in (('previousRevision', 1), ('entityVersion', 2)):
            proposal = copy.deepcopy(original)
            proposal[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
                await ledger.append(proposal, expected_sequence=0,
                    expected_target_version=1, completion_records=0)
        self.assertFalse(self.intent_js.messages)

    async def test_lost_ack_and_restart_replay_keep_original_bytes(self):
        admission, original = await self.retained_original()
        ledger = self.fresh_ledger()
        self.intent_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await ledger.append(original, expected_sequence=0, expected_target_version=1, completion_records=0)
        self.assertEqual(len(self.intent_js.messages), 1)
        replay = await self.reopen().append(original, expected_sequence=0, expected_target_version=1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, canonical_bytes(original))
        self.assertEqual(replay.sequence, 1)
        self.assertEqual((await RetainedContainerIntent(self.reopen(), admission.binding).check()).record,
            replay.record)
        self.assertEqual(len(self.intent_js.messages), 1)

    async def test_reused_operation_with_changed_content_refuses(self):
        _, original = await self.retained_original()
        changed = copy.deepcopy(original)
        changed['operation']['payloadDigest'] = payload_digest({'changed': True})
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.reopen().append(changed, expected_sequence=0,
                expected_target_version=1, completion_records=0)
        # A retry never overwrites an original with changed proposed state.
        changed = copy.deepcopy(original)
        changed['state']['executionPhase'] = 'running'
        replay = await self.reopen().append(changed, expected_sequence=0, expected_target_version=1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, canonical_bytes(original))
        self.assertEqual(len(self.intent_js.messages), 1)

    async def test_actual_caller_refuses_changed_binding_original_phase_or_effect(self):
        admission, original = await self.retained_original()
        binding = strict_loads(admission.binding)
        for mutate in (
                lambda r: r['operation'].update(traceId='substituted-trace'),
                lambda r: r['state']['executionBinding'].update(attemptId='other-attempt'),
                lambda r: r['state'].update(executionPhase='cancelled'),
                lambda r: r.update(effects=[])):
            changed = copy.deepcopy(original)
            mutate(changed)
            self.intent_js.messages[0].data = canonical_bytes(changed)
            with self.subTest(mutation=mutate), self.assertRaisesRegex(ContractError, '^execution_intent_required$'):
                await RetainedContainerIntent(self.reopen(), admission.binding).check()
        self.intent_js.messages[0].data = canonical_bytes(original)
        changed = copy.deepcopy(binding)
        changed['runRef']['id'] = 'execution-another-run'
        with self.assertRaisesRegex(ContractError, '^execution_intent_required$'):
            RetainedContainerIntent(self.reopen(), canonical_bytes(changed))
        self.assertFalse(self.commands)

    async def test_completion_capacity_remains_required(self):
        _, proposal = await self.retained_original()
        ledger = self.fresh_ledger()
        with self.assertRaisesRegex(ContractError, '^owner_completion_budget_required$'):
            await ledger.append(proposal, expected_sequence=0, expected_target_version=1)
        with self.assertRaisesRegex(ContractError, '^owner_completion_budget_invalid$'):
            await ledger.append(proposal, expected_sequence=0,
                expected_target_version=1, completion_records=-1)
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            await ledger.append(proposal, expected_sequence=0,
                expected_target_version=1, completion_records=1_000_000)
        self.assertFalse(self.intent_js.messages)

    async def test_current_append_deadline_remains_enforced_after_reads(self):
        _, proposal = await self.retained_original()
        ledger = self.fresh_ledger()
        original_info = self.intent_js.stream_info
        deadline = datetime(2026, 10, 9, 12, 0, 2, tzinfo=timezone.utc)
        calls = 0

        async def read_info(stream):
            nonlocal calls
            calls += 1
            return await original_info(stream)

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return deadline if calls >= 3 else deadline - timedelta(seconds=1)

        self.intent_js.stream_info = read_info
        with patch('state_owner.ledger.datetime', Clock):
            limit = Clock.fromisoformat(deadline.isoformat())
            with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
                await ledger.append(proposal, expected_sequence=0, expected_target_version=1,
                    completion_records=0, valid_until=limit)
        self.assertFalse(self.intent_js.messages)

    async def test_conditional_broker_conflict_never_retries(self):
        _, proposal = await self.retained_original()
        ledger = self.fresh_ledger()
        winner = copy.deepcopy(proposal)
        winner['recordId'] = 'record-other-original'
        winner['operation']['operationId'] = 'other-original'
        winner['authorizationDecision']['operationId'] = 'other-original'
        self.intent_js.race = winner
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await ledger.append(proposal, expected_sequence=0, expected_target_version=1, completion_records=0)
        self.assertEqual(len(self.intent_js.messages), 1)
        self.assertEqual((await ledger.current()).latest.record, canonical_bytes(winner))


# Reuse the actual caller's setup and methods, not its physical-adapter tests or
# the accepted A suite inherited through it.
for _name in dir(container_support.ContainerTests):
    if _name.startswith('test_') and _name not in vars(ExecutionIntentVersionTests):
        setattr(ExecutionIntentVersionTests, _name, None)
