"""Fresh signed admission before the original effect and its disclosure."""
from datetime import datetime, timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.test_authority import NOW, SEED, ref
from .test_work_bridge_owner import WorkBridgeFixture


class WorkBridgePreflightTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def test_real_admission_authenticates_once_before_and_after_original_effect(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker',
            'title': 'Original signed work', 'federate': True})
        authority = self.service.ingress._request_authority
        legacy = self.resource.legacy
        stages = []

        async def authenticate(request):
            checked = await authority(request)
            stages.append(('authority', len(self.store.q('SELECT * FROM work_items'))))
            return checked

        async def execute(*args, **kwargs):
            result = await legacy(*args, **kwargs)
            stages.append(('effect', len(self.store.q('SELECT * FROM work_items'))))
            return result

        with patch.object(self.service.ingress, '_request_authority', new=authenticate), \
                patch.object(self.resource, 'legacy', new=execute):
            result = await self.work_call(raw, include_valid_until=True)

        self.assertEqual(stages, [('authority', 0), ('effect', 1), ('authority', 1)])
        self.assertEqual(result['result']['outcome'], 'applied')
        self.assertLessEqual(datetime.fromisoformat(result['validUntil']),
            datetime.fromisoformat(strict_loads(raw)['claims']['expiresAt']))
        self.assertEqual(result['result']['result'], self.store.q1('SELECT * FROM work_items'))
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_actual_ingress_refuses_invalid_revoked_and_expired_before_effect(self):
        original_record = self.js.messages[-1].data
        authority = self.service.ingress._request_authority
        legacy = self.resource.legacy
        calls, errors = [], []

        async def authenticate(request):
            calls.append('authority')
            try:
                return await authority(request)
            except ContractError as error:
                errors.append(error.code)
                raise

        async def execute(*args, **kwargs):
            calls.append('effect')
            return await legacy(*args, **kwargs)

        cases = (
            ('signature', 'credential_possession_invalid'),
            ('transport', 'credential_unavailable'),
            ('principal', 'credential_grant_unavailable'),
            ('grant', 'credential_grant_unavailable'),
            ('expiry', 'credential_time_invalid'),
        )
        with patch.object(self.service.ingress, '_request_authority', new=authenticate), \
                patch.object(self.resource, 'legacy', new=execute):
            for kind, expected in cases:
                with self.subTest(authority=kind):
                    self.js.messages[-1].data = original_record
                    calls.clear()
                    errors.clear()
                    raw = self.work_request('create', {'target': 'role:falcon/worker',
                        'title': 'Refused signed work'}, operation='refused-' + kind)
                    packet = strict_loads(raw)
                    current = strict_loads(original_record)
                    if kind == 'signature':
                        packet['signature'] = sign_claims(packet['claims'], b'\x09' * 32)
                    elif kind == 'expiry':
                        packet['claims'].update(
                            issuedAt=(NOW - timedelta(seconds=2)).isoformat().replace('+00:00', 'Z'),
                            expiresAt=(NOW - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'))
                        packet['signature'] = sign_claims(packet['claims'], SEED)
                    else:
                        collection, reference = {
                            'transport': ('transports', ref('transport')),
                            'principal': ('identities', ref('human')),
                            'grant': ('grants', self.work_grants['human']['federation-work-create']),
                        }[kind]
                        next(value for value in current['state'][collection]
                            if value['ref'] == reference)['status'] = 'revoked'
                    self.js.messages[-1].data = canonical_bytes(current)
                    with self.assertRaises(ContractError):
                        await self.work_call(canonical_bytes(packet))
                    self.assertEqual(calls, ['authority'])
                    self.assertEqual(errors, [expected])
                    self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
                    self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
        self.js.messages[-1].data = original_record

    async def test_post_effect_revocation_refuses_disclosure_and_preserves_original_outcome(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker',
            'title': 'Original retained work', 'federate': True})
        authority = self.service.ingress._request_authority
        legacy = self.resource.legacy
        original_record = self.js.messages[-1].data
        stages, effects, errors = [], [], []

        async def authenticate(request):
            stages.append(('authority', len(self.store.q('SELECT * FROM work_items'))))
            try:
                return await authority(request)
            except ContractError as error:
                errors.append(error.code)
                raise

        async def execute(*args, **kwargs):
            result = await legacy(*args, **kwargs)
            effects.append(result)
            stages.append(('effect', len(self.store.q('SELECT * FROM work_items'))))
            current = strict_loads(original_record)
            grant = self.work_grants['human']['federation-work-create']
            next(value for value in current['state']['grants']
                if value['ref'] == grant)['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            return result

        with patch.object(self.service.ingress, '_request_authority', new=authenticate), \
                patch.object(self.resource, 'legacy', new=execute):
            with self.assertRaises(ContractError):
                await self.work_call(raw)

        self.assertEqual(stages, [('authority', 0), ('effect', 1), ('authority', 1)])
        self.assertEqual(errors, ['credential_grant_unavailable'])
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]['outcome'], 'applied')
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
        self.js.messages[-1].data = original_record
        recovered = await self.work_call(self.work_request('outcome', self.query(raw), operation='recover-original'))
        self.assertEqual({key: recovered[key] for key in effects[0]}, effects[0])
        self.assertEqual(await self.work_call(raw), effects[0])
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
