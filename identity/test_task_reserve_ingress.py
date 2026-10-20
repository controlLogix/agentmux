"""Admission uses real owner preparations and rechecks authority after storage reads."""
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.test_authority import NOW, SEED, ref
from state_owner import test_task as owner_support


class TaskReserveIngressTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.owner_case = owner_support.TaskReservationTests()
        self.owner_case.setUp()
        self.addCleanup(self.owner_case.doCleanups)

    def approved_request(self):
        case = self.owner_case
        request = strict_loads(case.possession())
        claims = request['claims']
        claims['approvalRefs'] = [ref('reserve-approval')]
        state = case.record['state']
        grant = next(g for g in state['grants'] if g['ref'] == ref('reserve-grant'))
        grant['decision'] = 'review-required'
        approver = copy.deepcopy(grant)
        approver.update(ref=ref('approve-grant'), contractId='identity-approve',
            resourceId='reserve-grant', decision='allowed')
        state['grants'].append(approver)
        state['approvals'] = [{'ref': ref('reserve-approval'), 'grantRef': grant['ref'],
            'approverRef': grant['actorRef'], 'approverGrantRef': ref('approve-grant'),
            'payloadDigest': payload_digest(claims['payload']),
            'audience': {'hubId': 'hub-one', 'serviceId': 'task-owner'},
            'operationId': claims['operationId'], 'expectedVersion': claims['expectedVersion'],
            'decision': 'approved', 'status': 'active', 'issuedAt': claims['issuedAt'],
            'expiresAt': claims['expiresAt']}]
        case.js.messages[0].data = canonical_bytes(case.record)
        request['signature'] = sign_claims(claims, bytes(reversed(SEED)))
        return canonical_bytes(request)

    async def test_current_exact_approval_allows_review_required_reservation(self):
        case = self.owner_case
        raw = self.approved_request()
        self.assertIsNone(await case.service.ingress.authorize_reservation_preparation(raw))
        _, prepared, envelope = await case.admitted(raw)
        result = await case.owner.handle(envelope, reservation_context=prepared)
        self.assertEqual(result.sequence, 2)

    async def test_invalid_approvals_refuse_before_owner_await(self):
        case = self.owner_case
        raw = self.approved_request()
        prepared = await case.owner.prepare_reservation(raw, case.cancel)
        pristine = copy.deepcopy(case.record)
        changes = [lambda s: s.update(approvals=[]),
            lambda s: s['approvals'][0].update(decision='rejected'),
            lambda s: s['approvals'][0].update(status='revoked'),
            lambda s: s['approvals'][0].update(expiresAt='2026-10-09T12:00:00Z'),
            lambda s: s['approvals'][0].update(payloadDigest='sha256:'+'0'*64),
            lambda s: s['approvals'][0].update(operationId='another-operation'),
            lambda s: s['approvals'][0].update(expectedVersion=9),
            lambda s: s['approvals'][0].update(audience={'hubId':'hub-one','serviceId':'other-owner'}),
            lambda s: s['grants'][-1].update(status='revoked'),
            lambda s: s['grants'][-2].update(decision='denied')]
        for change in changes:
            case.record = copy.deepcopy(pristine)
            change(case.record['state'])
            case.js.messages[0].data = canonical_bytes(case.record)
            with patch.object(case.ledger, 'current', side_effect=AssertionError('owner await')):
                with self.assertRaises(ContractError):
                    await case.service.ingress.authorize_reservation_preparation(raw)
                with self.assertRaises(ContractError):
                    await case.service.ingress.admit(raw, cancellation_ref=case.cancel,
                        reservation_context=prepared)
        self.assertEqual(len(case.task_js.messages), 1)

    async def test_approval_revoked_during_owner_await_returns_no_envelope(self):
        case = self.owner_case
        raw = self.approved_request()
        prepared = await case.owner.prepare_reservation(raw, case.cancel)
        read = case.ledger.current

        async def revoke_after_read():
            snapshot = await read()
            case.record['state']['approvals'][0]['status'] = 'revoked'
            case.js.messages[0].data = canonical_bytes(case.record)
            return snapshot

        with patch.object(case.ledger, 'current', side_effect=revoke_after_read):
            result = await case.service.ingress.admit(raw, cancellation_ref=case.cancel,
                reservation_context=prepared)
        self.assertIsNone(result.envelope)
        self.assertEqual(result.decision.reason, 'approval_binding_mismatch')

    async def test_missing_and_mapping_preparations_cannot_authorize(self):
        case = self.owner_case
        for context in (None, {'delegationRef': ref('delegation-new')}):
            with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_required$'):
                await case.service.ingress.admit(case.possession(), cancellation_ref=case.cancel,
                    reservation_context=context)
        self.assertEqual(len(case.task_js.messages), 1)

    async def test_owner_scope_mismatch_refuses_before_source_read(self):
        case = self.owner_case
        raw = case.possession()
        prepared = await case.owner.prepare_reservation(raw, case.cancel)
        scope = copy.deepcopy(case.record['state']['grants'][-1]['scope'])
        scope['projectId'] = 'another-project'
        case.record['state']['grants'][-1]['scope'] = scope
        membership = copy.deepcopy(case.record['state']['memberships'][0])
        membership.update(ref=ref('other-membership'), scope=scope)
        case.record['state']['memberships'].append(membership)
        case.js.messages[0].data = canonical_bytes(case.record)
        with patch.object(case.ledger, 'current', side_effect=AssertionError('task source read')):
            with self.assertRaisesRegex(ContractError, '^task_reservation_scope_mismatch$'):
                await case.service.ingress.admit(raw, cancellation_ref=case.cancel,
                    reservation_context=prepared)
        self.assertEqual(len(case.task_js.messages), 1)

    async def test_revocation_during_preparation_returns_no_dispatchable_envelope(self):
        case = self.owner_case
        raw = case.possession()
        prepared = await case.owner.prepare_reservation(raw, case.cancel)
        read = case.ledger.current

        async def revoke_after_task_read():
            snapshot = await read()
            case.record['state']['grants'][-1]['status'] = 'revoked'
            case.js.messages[0].data = canonical_bytes(case.record)
            return snapshot

        with patch.object(case.ledger, 'current', side_effect=revoke_after_task_read):
            result = await case.service.ingress.admit(raw, cancellation_ref=case.cancel,
                reservation_context=prepared)
        self.assertNotEqual(result.decision.outcome, 'allowed')
        self.assertIsNone(result.envelope)
        self.assertEqual(len(case.task_js.messages), 1)

    async def test_later_admission_cannot_extend_an_earlier_preparation(self):
        case = self.owner_case
        original = await case.owner.prepare_reservation(case.possession(), case.cancel)
        later = NOW + timedelta(seconds=20)
        with patch('identity.test_service.NOW', later):
            _, fresh, envelope = await case.admitted(case.possession(now=later))
        with patch('identity.test_service.NOW', NOW + timedelta(seconds=40)):
            with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
                await case.owner.handle(envelope, reservation_context=original)
            self.assertEqual(len(case.task_js.messages), 1)
            result = await case.owner.handle(envelope, reservation_context=fresh)
        self.assertEqual(result.sequence, 2)

    async def test_preflight_returns_no_proof_and_never_reads_task_state(self):
        case = self.owner_case
        with patch.object(case.ledger, 'current', side_effect=AssertionError('task state read')):
            self.assertIsNone(await case.service.ingress.authorize_reservation_preparation(case.possession()))
        self.assertEqual(len(case.task_js.messages), 1)

    async def test_preflight_checks_real_possession_and_current_direct_authority(self):
        case = self.owner_case
        raw = case.possession()
        pristine = copy.deepcopy(case.record)
        changes = [lambda s: s['transports'][0].update(status='revoked'),
            lambda s: s['issuers'][0].update(status='revoked'),
            lambda s: s['grants'][-1].update(status='revoked'),
            lambda s: s['grants'][-1].update(delegationRef=ref('delegated')),
            lambda s: s['grants'][-1].update(actorRef=ref('service')),
            lambda s: s['grants'][-1].update(resourceId='other-task'),
            lambda s: s.update(memberships=[]),
            lambda s: s['grants'][-1].update(decision='review-required')]
        with patch.object(case.ledger, 'current', side_effect=AssertionError('task state read')):
            for change in changes:
                case.record = copy.deepcopy(pristine)
                change(case.record['state'])
                case.js.messages[0].data = canonical_bytes(case.record)
                with self.assertRaises(ContractError):
                    await case.service.ingress.authorize_reservation_preparation(raw)
            case.record = pristine
            case.js.messages[0].data = canonical_bytes(pristine)
            for field, value in (('profileId','other'), ('contractId','task-inspect'),
                                 ('expiresAt','2026-10-09T12:00:00Z')):
                request = strict_loads(raw)
                request['claims'][field] = value
                request['signature'] = sign_claims(request['claims'], bytes(reversed(SEED)))
                with self.assertRaises(ContractError):
                    await case.service.ingress.authorize_reservation_preparation(canonical_bytes(request))
            request = strict_loads(raw)
            request['signature'] = sign_claims(request['claims'], SEED)
            with self.assertRaisesRegex(ContractError, '^credential_possession_invalid$'):
                await case.service.ingress.authorize_reservation_preparation(canonical_bytes(request))

    async def test_successful_preflight_does_not_bypass_later_revocation(self):
        case = self.owner_case
        raw = case.possession()
        await case.service.ingress.authorize_reservation_preparation(raw)
        prepared = await case.owner.prepare_reservation(raw, case.cancel)
        case.record['state']['grants'][-1]['status'] = 'revoked'
        case.js.messages[0].data = canonical_bytes(case.record)
        with self.assertRaisesRegex(ContractError, '^credential_grant_unavailable$'):
            await case.service.ingress.admit(raw, cancellation_ref=case.cancel, reservation_context=prepared)
        self.assertEqual(len(case.task_js.messages), 1)
