"""Actual IdentityService/OwnerLedger behavior over the existing offline broker."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity import test_service as service_fixture
from identity.test_authority import ref, NOW, SEED
from identity.test_ordinary_secret import ordinary_record, ordinary_state, resolution_fixture
from identity.ordinary_secret import verify_resolution
from identity.service import verify_receipt


class OrdinarySecretServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        service_fixture.ServiceTests.setUp(self)
        patch('identity.ordinary_secret.datetime', service_fixture._Clock).start()
        ordinary_state(self.record['state'])
        self.record['state']['grants'][0]['contractId'] = 'identity-ordinary-secret-set'
        self.record['state']['grants'].append({**copy.deepcopy(self.record['state']['grants'][0]),
            'ref': ref('ordinary-revoke-grant'), 'contractId': 'identity-revoke'})
        self.store()
        self.addAsyncCleanup(self.service.close)

    def store(self):
        self.js.messages = [SimpleNamespace(subject=self.service.ledger._subject, seq=1,
            data=canonical_bytes(self.record))]

    def request(self, *, contract='identity-ordinary-secret-set', payload=None, operation='ordinary-enroll',
                expected=1, actor='human', grant=None):
        claims = copy.deepcopy(self.claims)
        claims.update(contractId=contract, payload=payload or {'authorityId': 'authority-one',
            'record': ordinary_record(), 'previousRef': None}, operationId=operation, expectedVersion=expected,
            transportRef=ref('transport' if actor == 'human' else 'custody-transport'),
            grantRef=ref(grant or 'grant'))
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    async def test_enroll_replay_conflict_and_atomic_rejection_history(self):
        request = self.request()
        public = self.record['state']['issuers'][0]['publicKey']
        first = verify_receipt(await self.service.handle(request), request, public_key=public, issuer_ref=ref('issuer'))
        replay = verify_receipt(await self.service.handle(request), request, public_key=public, issuer_ref=ref('issuer'))
        self.assertEqual((first['decision'], first['sequence'], replay['replayed'], replay['sequence']),
            ('allowed', 2, True, 2))
        changed = {'authorityId': 'authority-one', 'record': ordinary_record('different-one'), 'previousRef': None}
        with self.assertRaises(ContractError): await self.service.handle(self.request(payload=changed))
        stale = self.request(payload=changed, operation='ordinary-stale')
        rejected = verify_receipt(await self.service.handle(stale), stale, public_key=public, issuer_ref=ref('issuer'))
        self.assertEqual((rejected['decision'], rejected['reason']), ('denied', 'identity_version_conflict'))
        state = strict_loads((await self.service.ledger.current()).latest.record)['state']
        self.assertEqual([row['ref']['id'] for row in state['ordinarySecretReferences']], ['ordinary-one'])
        self.assertNotIn('ordinarySecretReferences', self.record['state'])

    async def test_rotation_keeps_original_generation_tombstone(self):
        await self.service.handle(self.request())
        payload = {'authorityId': 'authority-one', 'record': ordinary_record('ordinary-two'),
            'previousRef': ref('ordinary-one')}
        raw = self.request(payload=payload, operation='ordinary-rotate', expected=2)
        reply = verify_receipt(await self.service.handle(raw), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual(reply['decision'], 'allowed')
        current = strict_loads((await self.service.ledger.current()).latest.record)
        rows = current['state']['ordinarySecretReferences']
        self.assertEqual((rows[0]['status'], rows[0]['ref']['revision']), ('revoked', 2))
        self.assertEqual(rows[0]['generationRef'], ref('ordinary-one'))
        self.assertEqual(rows[1]['generationRef'], ref('ordinary-two'))
        self.assertEqual(current['authorizationDecision']['operationId'], 'ordinary-rotate')

    async def test_signed_resolution_rechecks_current_original_and_custody_authority(self):
        fixture, outer, _ = resolution_fixture()
        self.record['state'] = fixture['state']
        self.store()
        raw = self.request(contract='identity-ordinary-secret-resolve', payload=outer['payload'],
            operation='ordinary-resolve', expected=0, actor='custody', grant='ordinary-resolve-grant')
        response = await self.service.handle(raw)
        claims = verify_resolution(response, raw, public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'), now=NOW)
        self.assertEqual(claims['callerRef'], ref('human'))
        self.assertEqual(claims['custodyIdentityRef'], ref('custody'))
        self.assertEqual((await self.service.ledger.current()).sequence, 1)
        bad = strict_loads(raw); bad['claims']['operationId'] = 'different-request'
        with self.assertRaises(ContractError):
            verify_resolution(response, canonical_bytes(bad),
                public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'), now=NOW)
        for name in ('ordinary-use-grant', 'ordinary-resolve-grant'):
            saved = copy.deepcopy(self.record)
            next(row for row in self.record['state']['grants'] if row['ref']['id'] == name)['status'] = 'revoked'
            self.store()
            with self.assertRaises(ContractError): await self.service.handle(raw)
            self.record = saved
