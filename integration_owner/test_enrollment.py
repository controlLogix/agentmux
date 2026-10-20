"""Restore synthetic private enrollment without recreating its original pin."""
import copy
import os
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from integration_owner import test_credentials as support
from integration_owner.enrollment import enrollment_bytes, load_atlassian_enrollment, write_atlassian_enrollment


class EnrollmentTests(unittest.TestCase):
    setUp = support.AtlassianCredentials.setUp
    write = support.AtlassianCredentials.write

    def load(self, raw):
        return load_atlassian_enrollment(raw, credential_ref=self.reference, provider='jira')

    def test_round_trip_restores_exact_pin_without_repinning(self):
        raw = enrollment_bytes(self.pin)
        self.assertNotIn(self.config['api_token'].encode(), raw)
        with patch('integration_owner.credentials.pin_atlassian_config', side_effect=AssertionError('never repin')):
            resolver = self.load(raw)
        self.assertEqual(resolver._pin, self.pin)
        self.assertEqual(resolver.resolve(self.reference, provider='jira', config_version=4).private_copy(), self.config)

    def test_explicit_private_writer_creates_once_and_preserves_existing_pin(self):
        path = self.directory.resolve() / 'enrollment.json'
        digest = write_atlassian_enrollment(path, self.pin)
        self.assertRegex(digest, r'^sha256:[a-f0-9]{64}$')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        raw = path.read_bytes()
        self.assertEqual(self.load(raw)._pin, self.pin)
        with self.assertRaises(FileExistsError):
            write_atlassian_enrollment(path, self.pin)
        self.assertEqual(path.read_bytes(), raw)

    def test_changed_config_or_identical_replacement_cannot_recover_old_enrollment(self):
        raw = enrollment_bytes(self.pin)
        self.write({**self.config, 'api_token': 'SYNTHETIC-ROTATED'})
        with self.assertRaisesRegex(ContractError, '^integration_enrollment_unavailable$'):
            self.load(raw)
        self.write(self.config)
        replacement = self.directory / 'replacement'
        replacement.write_bytes(self.path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        with self.assertRaisesRegex(ContractError, '^integration_enrollment_unavailable$'):
            self.load(raw)

    def test_closed_metadata_and_exact_reference_provider_version(self):
        value = strict_loads(enrollment_bytes(self.pin))
        variants = [('credentialRef', {**self.reference, 'id': 'other'}), ('provider', 'confluence'),
            ('configVersion', 5), ('configVersion', True), ('fileIdentity', ['1'] * 8),
            ('directoryIdentity', ['1'] * 4), ('configFingerprint', 'bad'), ('configPath', 'relative')]
        for key, replacement in variants:
            with self.subTest(key=key):
                changed = copy.deepcopy(value)
                changed[key] = replacement
                with self.assertRaisesRegex(ContractError, '^integration_enrollment_unavailable$'):
                    self.load(canonical_bytes(changed))
        changed = dict(value, token='untrusted')
        with self.assertRaises(ContractError):
            self.load(canonical_bytes(changed))
        for raw in (b'', b'[]', b'x' * 65537, b'not-json'):
            with self.assertRaises(ContractError):
                self.load(raw)
