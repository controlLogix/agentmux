"""Explicit protected-store provisioning and retained enrollment, without a broker."""
from pathlib import Path
import tempfile
import unittest
import os
from unittest.mock import patch
from agentmux_contracts import ContractError
from native_security.descriptor_admission import AdmissionError

from identity.application_enrollment import provision_application_attestor, load_application_attestor
from identity.test_authority import fixture, ref
from identity.transitions import transition


class ApplicationEnrollmentTests(unittest.TestCase):
    def test_fifo_and_malformed_store_are_refused_without_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'attestor.key'
            os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(ContractError, 'application_key_store_invalid'):
                load_application_attestor(path)
            path.unlink()
            path.write_bytes(b'{}'); path.chmod(0o600)
            with self.assertRaisesRegex(ContractError, 'application_key_store_invalid'):
                load_application_attestor(path)

    def test_native_acl_or_mount_refusal_is_not_replaced_by_mode_bits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'attestor.key'
            with patch('identity.application_enrollment.check_descriptor',
                       side_effect=AdmissionError('native_admission_acl')):
                with self.assertRaisesRegex(ContractError, 'application_key_store_native_refused'):
                    load_application_attestor(path)

    def test_explicit_private_key_provision_and_possession_enrollment(self):
        record, _ = fixture()
        identity = {'ref': ref('application-observer'), 'kind': 'service', 'status': 'active',
                    'principalId': 'application-observer', 'externalIdentity': None}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'attestor.key'
            args = dict(profile_id='profile-one', authority_id='authority-one', instance_id='application-one',
                identity=identity, issuer_ref=ref('application-issuer'), transport_ref=ref('application-transport'),
                ingress_issuer_ref=ref('issuer'), issued_at='2026-10-09T12:00:00Z', expires_at='2026-10-10T12:00:00Z')
            payload = provision_application_attestor(path, **args)
            state = transition(record['state'], 'identity-enroll', payload, hub_id='hub-one')
            self.assertEqual(state['identities'][-1], identity)
            signer = load_application_attestor(path)
            self.assertEqual(signer.public_key, payload['issuers'][0]['record']['publicKey'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('seed', repr(signer))
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                provision_application_attestor(path, **args)
            self.assertEqual(path.read_bytes(), original)
