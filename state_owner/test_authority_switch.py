"""Retained FAIL-48 authority-switch barrier and recovery permit checks."""
import copy
import asyncio
from datetime import timedelta
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.test_authority import fixture, ref, SEED, NOW
from identity.test_service import ServiceTests as _ServiceTests, _Clock
from state_owner.authority_switch import (AuthoritySwitchHost, AuthoritySwitchOwner,
    VerifiedLegacyRecoveryPermit, authority_switch_id)
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream


class AuthoritySwitchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _ServiceTests.setUp(self)
        patch('state_owner.authority_switch.datetime', _Clock).start()
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.source = {'sourceRef': ref('legacy-source'), 'applicationVersion': 'legacy-v1',
            'comparisonDigest': 'sha256:'+'a'*64, 'fenceId': 'f'+'b'*32, 'fenceGeneration': 1}
        self.switch_id = authority_switch_id(self.source)
        self.record['state']['memberships'][0]['scope'] = copy.deepcopy(self.scope)
        self.record['state']['grants'][0].update(scope=copy.deepcopy(self.scope),
            contractId='authority-switch', resourceId=self.switch_id)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.binding = OwnerBinding('hub-one', 'authority-switch', self.switch_id,
            'authority-switch', canonical_bytes(self.scope))
        self.switch_js = FakeJetStream(self.policy)
        self.switch_js.config.subjects = [owner_subject(self.binding)]
        self.switch_js.messages = []
        self.ledger = OwnerLedger(self.switch_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        self.directory = tempfile.TemporaryDirectory(prefix='authority-switch-')
        self.addCleanup(self.directory.cleanup)
        Path(self.directory.name).chmod(0o700)
        self.host = AuthoritySwitchHost(str(Path(self.directory.name).resolve()), binding=self.binding,
            stream_identity=StreamIdentity(CREATED, 0))
        self.owner = AuthoritySwitchOwner(self.service.reader, self.ledger, host=self.host)

    def envelope(self, action, *, operation=None, expected=None, source=None, reverse_evidence=None):
        _, envelope = fixture()
        payload = {'action': action, 'switchId': self.switch_id,
            'source': copy.deepcopy(source or self.source)}
        if reverse_evidence is not None:
            payload['reverseEvidence'] = reverse_evidence
        envelope.update(contractId='authority-switch', destinationServiceId='authority-switch-owner',
            payload=payload)
        version = {'record-source-fence': 0, 'open-target-admission': 1,
            'fence-target': 2, 'verify-reverse-migration': 3}.get(action,
                len(self.switch_js.messages))
        envelope['operation'].update(operationId=operation or action.replace('-', '_'),
            expectedVersion=version if expected is None else expected,
            scope=copy.deepcopy(self.scope), grantRef=ref('grant'), taskId=None, runId=None,
            attemptId=None, delegationRef=None, payloadDigest=payload_digest(payload))
        claims = envelope['ingressAttestation']['claims']
        claims.update(contractId='authority-switch', operation=copy.deepcopy(envelope['operation']),
            audience={'hubId': 'hub-one', 'serviceId': 'authority-switch-owner'})
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def source_fenced(self):
        return await self.owner.handle(self.envelope('record-source-fence'))

    async def test_exact_source_fence_replay_and_current_signed_recovery_permit(self):
        stored = await self.source_fenced()
        replay = await self.owner.handle(self.envelope('record-source-fence'))
        self.assertTrue(replay.replayed)
        self.assertEqual((stored.record, stored.sequence), (replay.record, 1))
        self.assertEqual(self.host.latest().stored.record, stored.record)
        permit = await self.owner.handle(self.envelope('request-recovery', expected=1))
        self.assertIs(type(permit), VerifiedLegacyRecoveryPermit)
        self.assertEqual(self.host.latest().stored.sequence, 2)
        self.assertTrue(await self.owner.validate_recovery_permit(permit, source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2)))
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
            await self.owner.validate_recovery_permit(permit,
                source={**self.source, 'applicationVersion': 'changed'}, switch_id=self.switch_id,
                stream_identity=StreamIdentity(CREATED, 2))
        class ExpiredClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW+timedelta(minutes=20)
        with patch('state_owner.authority_switch.datetime', ExpiredClock):
            with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
                await self.owner.validate_recovery_permit(permit, source=self.source,
                    switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        with self.assertRaisesRegex(ContractError, '^authority_switch_transition_refused$'):
            await self.owner.handle(self.envelope('open-target-admission'))
        with self.assertRaisesRegex(ContractError, '^authority_switch_transition_refused$'):
            await self.owner.handle(self.envelope('fence-target', operation='fence_after_recovery'))
        self.assertEqual(len(self.switch_js.messages), 2)
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
            await self.owner.validate_recovery_permit(permit, source=self.source,
                switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        with self.assertRaisesRegex(ContractError, '^authority_switch_access_refused$'):
            await self.owner.handle(self.envelope('request-recovery', operation='second_recovery', expected=1))

    async def test_target_barrier_is_monotonic_survives_restart_and_blocks_recovery(self):
        await self.source_fenced()
        barrier = await self.owner.handle(self.envelope('open-target-admission'))
        state = strict_loads(barrier.record)['state']
        self.assertEqual((state['phase'], state['targetAdmissionRevision']),
            ('target-admission-open', 2))
        restarted = OwnerLedger(self.switch_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        owner = AuthoritySwitchOwner(self.service.reader, restarted, host=self.host)
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
            await owner.handle(self.envelope('request-recovery', expected=1))
        fenced = await owner.handle(self.envelope('fence-target'))
        self.assertEqual(strict_loads(fenced.record)['state']['phase'], 'target-fenced')
        with self.assertRaisesRegex(ContractError, '^authority_switch_transition_refused$'):
            await owner.handle(self.envelope('open-target-admission', operation='late_open'))

    async def test_recovery_permit_expiry_is_rechecked_after_owner_reads(self):
        await self.source_fenced()
        permit = await self.owner.handle(self.envelope('request-recovery', expected=1))

        class AdvancingClock(_Clock):
            current = NOW

            @classmethod
            def now(cls, tz=None):
                return cls.current

        original_current = self.owner._current

        async def current_then_expire():
            result = await original_current()
            AdvancingClock.current = NOW+timedelta(minutes=20)
            return result

        async def authorized(_raw, _request):
            return None

        with (patch('state_owner.authority_switch.datetime', AdvancingClock),
                patch.object(self.owner, '_current', side_effect=current_then_expire),
                patch.object(self.owner, '_authorize', side_effect=authorized)):
            with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
                await self.owner.validate_recovery_permit(permit, source=self.source,
                    switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))

    async def test_recovery_and_target_open_compete_on_one_committed_revision(self):
        await self.source_fenced()
        first = AuthoritySwitchOwner(self.service.reader, self.ledger)
        second_ledger = OwnerLedger(self.switch_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        second = AuthoritySwitchOwner(self.service.reader, second_ledger)
        results = await asyncio.gather(
            first.handle(self.envelope('request-recovery', operation='race_recovery', expected=1)),
            second.handle(self.envelope('open-target-admission', operation='race_target_open', expected=1)),
            return_exceptions=True)
        self.assertEqual(len(self.switch_js.messages), 2)
        state = strict_loads(self.switch_js.messages[-1].data)['state']
        self.assertIn(state['phase'], ('source-recovery-authorized', 'target-admission-open'))
        self.assertEqual(sum(not isinstance(result, Exception) for result in results), 1)
        self.assertEqual(sum(isinstance(result, ContractError) for result in results), 1)
        if state['phase'] == 'source-recovery-authorized':
            permit = next(result for result in results
                if type(result) is VerifiedLegacyRecoveryPermit)
            self.assertTrue(await first.validate_recovery_permit(permit, source=self.source,
                switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2)))
        else:
            self.assertFalse(any(type(result) is VerifiedLegacyRecoveryPermit for result in results))

    async def test_host_floor_refuses_rolled_back_or_recreated_target_stream(self):
        await self.source_fenced()
        await self.owner.handle(self.envelope('open-target-admission'))
        self.switch_js.messages = self.switch_js.messages[:1]
        rolled_back = OwnerLedger(self.switch_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        owner = AuthoritySwitchOwner(self.service.reader, rolled_back, host=self.host)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await owner.handle(self.envelope('request-recovery', expected=1))
        self.switch_js.created = CREATED.replace(year=CREATED.year+1)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await owner.handle(self.envelope('request-recovery', expected=1))

    async def test_reverse_request_never_accepts_caller_claimed_evidence(self):
        await self.source_fenced()
        await self.owner.handle(self.envelope('open-target-admission'))
        await self.owner.handle(self.envelope('fence-target'))
        for evidence in ({'verified': True}, {'checkpointReceipt': {'cursor': 3}},
                {'callbackResult': 'success'}):
            with self.subTest(evidence=evidence):
                with self.assertRaisesRegex(ContractError, '^authority_switch_reverse_incomplete$'):
                    await self.owner.handle(self.envelope('verify-reverse-migration',
                        operation='reverse_'+str(len(canonical_bytes(evidence))), reverse_evidence=evidence))
        self.assertEqual(len(self.switch_js.messages), 3)

    async def test_changed_payload_replay_conflicts_and_out_of_order_refuses(self):
        await self.source_fenced()
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.owner.handle(self.envelope('open-target-admission',
                operation='record_source_fence'))
        self.switch_js.messages = []
        other_ledger = OwnerLedger(self.switch_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0))
        other = AuthoritySwitchOwner(self.service.reader, other_ledger)
        with self.assertRaisesRegex(ContractError, '^authority_switch_transition_refused$'):
            await other.handle(self.envelope('open-target-admission'))

    async def test_lost_append_reply_replays_and_repairs_host_inventory(self):
        self.switch_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.source_fenced()
        self.assertIsNone(self.host.latest())
        self.switch_js.lose_ack = False
        replay = await self.source_fenced()
        self.assertTrue(replay.replayed)
        self.assertEqual(self.host.latest().stored.record, replay.record)

    async def test_corrupt_or_replaced_host_observation_fails_closed(self):
        await self.source_fenced()
        path = next(Path(self.directory.name).glob('authority-switch-*.json'))
        path.write_bytes(b'{}')
        with self.assertRaisesRegex(ContractError, '^authority_switch_observation_unavailable$'):
            self.host.latest()

    async def test_cross_source_switch_and_forged_plain_permit_refuse(self):
        changed = {**self.source, 'applicationVersion': 'changed'}
        with self.assertRaisesRegex(ContractError, '^authority_switch_binding_mismatch$'):
            await self.owner.handle(self.envelope('record-source-fence', source=changed))
        forged = object.__new__(VerifiedLegacyRecoveryPermit)
        object.__setattr__(forged, '_seal', object())
        object.__setattr__(forged, '_receipt', canonical_bytes({'decision': 'pre-cutover-abort'}))
        object.__setattr__(forged, '_request', b'{}')
        with self.assertRaisesRegex(ContractError, '^authority_switch_recovery_refused$'):
            await self.owner.validate_recovery_permit(forged, source=self.source,
                switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 1))


if __name__ == '__main__':
    unittest.main()
