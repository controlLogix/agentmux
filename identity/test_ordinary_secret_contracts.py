"""Python/TypeScript wire checks for the public ordinary-secret boundary."""
import copy
import os
import sys
import unittest

from agentmux_contracts import payload_digest, sign_claims
from identity.test_authority import ref, SEED
from identity.test_ordinary_secret import ordinary_record, resolution_fixture
from tests.contracts.test_conformance import Client


class OrdinarySecretContractTests(unittest.TestCase):
    def test_two_clients_agree_on_public_shapes_and_private_field_refusals(self):
        record, outer, _ = resolution_fixture()
        from identity.authority import AuthoritySnapshot
        from identity.ordinary_secret import resolve_snapshot
        from agentmux_contracts import canonical_bytes
        from identity.test_authority import NOW
        resolved = resolve_snapshot(AuthoritySnapshot(canonical_bytes(record), 17), canonical_bytes(outer),
            audience={'hubId': 'hub-one', 'serviceId': 'identity-owner'}, now=NOW)
        claims = {'purpose': 'agentmux-ordinary-secret-resolution-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one', 'issuerRef': ref('issuer'),
            'requestDigest': payload_digest(outer), 'operationId': outer['operation']['operationId'],
            **resolved.claims(), 'issuedAt': '2026-10-09T12:00:02Z', 'validUntil': '2026-10-09T12:05:00Z'}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims, 'signature': sign_claims(claims, SEED)}
        vectors = {'identity-ordinary-secret-reference': ordinary_record(),
            'identity-ordinary-secret-set': {'authorityId': 'authority-one',
                'record': ordinary_record(), 'previousRef': None},
            'identity-ordinary-secret-resolve': outer['payload'],
            'identity-ordinary-secret-resolution': response}
        requests, expected = [], []
        for name, value in vectors.items():
            requests.append({'op': 'validate', 'schema': name, 'value': value}); expected.append(True)
            for field in ('secretBytes', 'path', 'reasoning'):
                invalid = copy.deepcopy(value); invalid[field] = 'private-value'
                requests.append({'op': 'validate', 'schema': name, 'value': invalid}); expected.append(False)
        invalid = copy.deepcopy(outer['payload'])
        invalid['originalEnvelope']['payload']['secretBytes'] = 'private-value'
        requests.append({'op': 'validate', 'schema': 'identity-ordinary-secret-resolve', 'value': invalid})
        expected.append(False)
        requests.append({'op': 'sign', 'claims': claims, 'seedHex': SEED.hex()})
        for language in ('python', 'typescript'):
            client = Client(language)
            if language == 'python':
                # Reuse the running test's prepared dependencies; no installation
                # is needed when they live outside the interpreter directory.
                client.env['PYTHONPATH'] = os.pathsep.join(sys.path)
            results = client.many(requests)
            with self.subTest(language=language):
                self.assertEqual([r['ok'] for r in results[:-1]], expected)
                self.assertEqual(results[-1], {'ok': True, 'result': response['signature']})
