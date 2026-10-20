"""Fresh native evidence cannot replace an accepted execution original."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.test_process_native_delivery import ProcessNativeDeliveryTests
from identity.execution_evidence import NativeExecutionEvidence
from identity.test_authority import ref, SEED


class NativeExecutionEvidenceTests(ProcessNativeDeliveryTests):
    def retained_native(self, case):
        return canonical_bytes(strict_loads(case['first'])['state']['nativeBinding'])

    def evidence(self, wrapper):
        return NativeExecutionEvidence(wrapper, self.plans._ingress,
            canonical_bytes(ref('plugin')), 'plugin-one', 'test-plugin')

    def retained_fingerprint(self):
        # Assertions expose digests, never the saved envelopes or credentials.
        digest = lambda value: hashlib.sha256(value).hexdigest()
        return (tuple(digest(item.data) for item in self.execution_js.messages),
            tuple(digest(item.data) for item in self.credential_js.messages),
            digest(canonical_bytes(self.run)), tuple(self.commands),
            self.engine.exec_fixed.await_count)

    def signed_change(self, original, *, operation=None, payload=None):
        envelope = strict_loads(original)
        if operation is not None:
            envelope['operation'].update(copy.deepcopy(operation))
        if payload is not None:
            envelope['payload'] = copy.deepcopy(payload)
            envelope['operation']['payloadDigest'] = payload_digest(payload)
        claims = envelope['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def test_signed_business_changes_cannot_replace_original(self):
        case = await self.prepare_native_original()
        retained = self.retained_native(case)
        before = self.retained_fingerprint()
        _, _, accepted = await case['evidence'].authorize(self.service.reader,
            case['raw'], retained=retained)
        self.assertEqual(accepted, retained)
        original = strict_loads(case['raw'])
        changes = (
            ('deadline', {'deadline': (datetime.fromisoformat(original['operation']['deadline'])
                + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')}),
            ('actor', {'effectiveActorRef': ref('administrator')}),
            ('caller', {'caller': {'kind': 'service', 'principalId': 'administrator',
                'authenticatedIdentityRef': ref('administrator')}}),
            ('project', {'scope': {**self.scope, 'projectId': 'another-project'}}),
            ('organization', {'scope': {**self.scope, 'organizationId': 'another-org'}}),
            ('grant', {'grantRef': ref('another-grant')}),
            ('task', {'taskId': 'another-task'}),
            ('attempt', {'attemptId': 'another-attempt'}),
            ('run', {'runId': 'another-run'}),
            ('cancellation', {'cancellationRef': ref('another-cancellation')}),
            ('trace', {'traceId': 'another-trace'}),
            ('version', {'expectedVersion': 2}),
        )
        alternatives = [(name, self.signed_change(case['raw'], operation=change))
            for name, change in changes]
        payload = copy.deepcopy(original['payload'])
        payload['input']['planRef']['revision'] += 1
        alternatives.append(('payload', self.signed_change(case['raw'], payload=payload)))
        for name, changed in alternatives:
            with self.subTest(field=name):
                with self.assertRaisesRegex(ContractError, '^execution_native_evidence_refused$'):
                    await case['evidence'].authorize(self.service.reader, changed, retained=retained)
                with self.assertRaisesRegex(ContractError, '^execution_original_conflict$'):
                    await case['execution'].start(changed, task_inspection=self.inspection(),
                        native_evidence=case['evidence'])
                self.assertEqual(self.retained_fingerprint(), before)

    async def test_actual_provider_other_request_cannot_supply_original_run(self):
        case = await self.prepare_native_original()
        before = self.retained_fingerprint()
        changed, wrapper = await self.delivery(case['source'], case['row'],
            case['authority_ref'], 'request_' + 'd' * 64)
        self.assertNotEqual(strict_loads(changed)['operation']['operationId'],
            strict_loads(case['raw'])['operation']['operationId'])
        evidence = self.evidence(wrapper)
        with self.assertRaisesRegex(ContractError, '^execution_native_evidence_refused$'):
            await evidence.authorize(self.service.reader, case['raw'],
                retained=self.retained_native(case))
        with self.assertRaisesRegex(ContractError, '^execution_native_evidence_refused$'):
            await case['execution'].start(case['raw'], task_inspection=self.inspection(),
                native_evidence=evidence)
        self.assertEqual(self.retained_fingerprint(), before)

    async def test_actual_expired_delivery_cannot_admit_another_effect(self):
        case = await self.prepare_native_original()
        before = self.retained_fingerprint()
        await asyncio.sleep(max(0, (case['expiry'] - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        with self.assertRaisesRegex(ContractError, '^capability_service_expired$'):
            await case['evidence'].authorize(self.service.reader, case['raw'],
                retained=self.retained_native(case))
        with self.assertRaisesRegex(ContractError, '^capability_service_expired$'):
            await case['execution'].dispatch(case['raw'], task_inspection=self.inspection(),
                native_evidence=case['evidence'])
        self.assertEqual(self.retained_fingerprint(), before)

    async def test_actual_admin_revocation_refuses_prepared_current_evidence(self):
        case = await self.prepare_native_original()
        before = self.retained_fingerprint()
        _, wrapper = await self.delivery(case['source'], case['row'],
            case['authority_ref'], case['request_id'])
        evidence = self.evidence(wrapper)
        await evidence.authorize(self.service.reader, case['raw'],
            retained=self.retained_native(case))
        grant = strict_loads(case['raw'])['operation']['grantRef']
        receipt = await self.admin('identity-revoke', {'authorityId': 'authority-one',
            'targetRef': grant})
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        with self.assertRaisesRegex(ContractError, '^capability_service_not_authorized$'):
            await evidence.authorize(self.service.reader, case['raw'],
                retained=self.retained_native(case))
        with self.assertRaisesRegex(ContractError, '^capability_service_not_authorized$'):
            await case['execution'].dispatch(case['raw'], task_inspection=self.inspection(),
                native_evidence=evidence)
        self.assertEqual(self.retained_fingerprint(), before)

    async def test_actual_extended_native_replacement_cannot_renew_first_ceiling(self):
        case = await self.prepare_native_original()
        before = self.retained_fingerprint()
        row = copy.deepcopy(case['row'])
        previous = copy.deepcopy(row['ref'])
        row['ref']['revision'] += 1
        for kind in ('grant', 'policy'):
            row['facts'][kind]['expiresAt'] = (datetime.fromisoformat(row['facts'][kind]['expiresAt'])
                + timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
        receipt = await self.admin('identity-native-instance-set', {'authorityId': 'authority-one',
            'record': row, 'previousRef': previous})
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        _, wrapper = await self.delivery(case['source'], row, case['authority_ref'], case['request_id'])
        evidence = self.evidence(wrapper)
        with self.assertRaisesRegex(ContractError, '^execution_native_evidence_refused$'):
            await evidence.authorize(self.service.reader, case['raw'],
                retained=self.retained_native(case))
        with self.assertRaisesRegex(ContractError, '^execution_native_evidence_refused$'):
            await case['execution'].start(case['raw'], task_inspection=self.inspection(),
                native_evidence=evidence)
        self.assertEqual(self.retained_fingerprint(), before)


for _name in dir(ProcessNativeDeliveryTests):
    if _name.startswith('test_') and _name not in vars(NativeExecutionEvidenceTests):
        setattr(NativeExecutionEvidenceTests, _name, None)
