"""Client receipt verification with server imports explicitly refused."""
import base64
import builtins
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from integration_owner import receipts


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.public_key = base64.urlsafe_b64encode(bytes(SigningKey(self.seed).verify_key)).decode().rstrip('=')
        ref = lambda name: {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}
        self.issuer = ref('issuer')
        self.payload = {'effectRef': {**ref('effect-one'), 'revision': 0}, 'credentialRef': ref('jira-account'),
            'action': 'jira-transition', 'target': {'issueKey': 'AMUX-66', 'transitionId': '31'}, 'contentRef': None}
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one', 'transportRef': ref('transport'),
            'grantRef': ref('grant'), 'operationId': 'operation-one', 'expectedVersion': 0,
            'contractId': 'integration-intent', 'payload': self.payload, 'approvalRefs': [ref('approval')],
            'issuedAt': '2026-10-16T12:00:00Z', 'expiresAt': '2026-10-16T12:00:50Z'}
        self.request = {'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, self.seed)}
        self.outcome = {'operationId': 'operation-one', 'originalOperationId': 'operation-one',
            'originalPayloadDigest': payload_digest(self.payload), 'sequence': 1,
            'attemptOperationId': None, 'phase': 'intent-committed'}
        self.claims = {'purpose': 'agentmux-integration-command-receipt-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one', 'issuerRef': self.issuer,
            'requestDigest': payload_digest(self.request), 'receipt': self.outcome}

    def response(self, claims=None):
        claims = self.claims if claims is None else claims
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, self.seed)})

    def verify(self, response, request=None, verifier=receipts.verify_receipt):
        return verifier(response, canonical_bytes(self.request if request is None else request),
                        public_key=self.public_key, issuer_ref=self.issuer)

    def test_client_module_loads_and_verifies_without_server_dependencies(self):
        original_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.split('.')[0] in {'identity', 'state_owner', 'taskmgmt', 'nats'}:
                raise AssertionError('server dependency: ' + name)
            return original_import(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location('integration_owner._client_receipt_probe',
                                                     Path(receipts.__file__))
        module = importlib.util.module_from_spec(spec)
        with patch('builtins.__import__', side_effect=guarded):
            spec.loader.exec_module(module)
            self.assertEqual(self.verify(self.response(), verifier=module.verify_receipt), self.outcome)

    def test_server_reexports_the_same_verifier(self):
        from integration_owner.service import verify_receipt
        self.assertIs(verify_receipt, receipts.verify_receipt)

    def test_exact_request_signature_and_closed_schema(self):
        self.assertEqual(self.verify(self.response()), self.outcome)
        changed = copy.deepcopy(self.request)
        changed['claims']['operationId'] = 'other-operation'
        with self.assertRaisesRegex(ContractError, '^integration_receipt_binding$'):
            self.verify(self.response(), changed)
        changed_claims = dict(self.claims, extra='untrusted')
        with self.assertRaisesRegex(ContractError, '^integration_receipt_invalid$'):
            self.verify(self.response(changed_claims))
        wrong = bytes(reversed(self.seed))
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': self.claims,
                               'signature': sign_claims(self.claims, wrong)})
        with self.assertRaisesRegex(ContractError, '^credential_possession_invalid$'):
            self.verify(raw)

    def test_even_signed_receipt_must_preserve_original_digest_and_intent_phase(self):
        for field, value in (('originalOperationId', 'other-operation'),
                             ('originalPayloadDigest', 'sha256:' + 'a' * 64),
                             ('phase', 'applied'), ('sequence', 2), ('attemptOperationId', 'other-attempt')):
            with self.subTest(field=field):
                claims = copy.deepcopy(self.claims)
                claims['receipt'][field] = value
                with self.assertRaisesRegex(ContractError, '^integration_receipt_binding$'):
                    self.verify(self.response(claims))

    def test_unsigned_unconfirmed_response_never_becomes_a_receipt(self):
        with self.assertRaisesRegex(ContractError, '^integration_outcome_unconfirmed$'):
            self.verify(canonical_bytes({'schemaVersion': '1.0.0', 'error': 'integration_outcome_unconfirmed'}))
