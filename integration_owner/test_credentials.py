"""Credential resolution checks using temporary files and synthetic secrets."""
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from integration_owner.credentials import (AtlassianCredentialResolver,
    PrivateAtlassianConfig, pin_atlassian_config)
from taskmgmt import atlassian


class AtlassianCredentials(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix='agentmux-credential-binding-')
        self.addCleanup(fixture.cleanup)
        self.directory = Path(fixture.name)
        self.path = self.directory / 'atlassian.json'
        self.reference = {'id': 'jira-account', 'ownerHubId': 'hub-one', 'revision': 4}
        self.config = {'deployment': 'cloud', 'base_url': 'https://fixture.atlassian.example',
            'email': 'synthetic@example.invalid', 'api_token': 'SYNTHETIC-PRIVATE-TOKEN',
            'jira_project': 'TEST', 'confluence_space': 'DOCS',
            'future': {'preserved': True, 'native_counter': 9007199254740993}}
        self.write(self.config)
        self.metadata = {'provider': 'jira', 'config_path': self.path,
            'site_url': self.config['base_url'], 'config_version': self.reference['revision']}
        self.pin = pin_atlassian_config(self.reference, **self.metadata)
        self.resolver = AtlassianCredentialResolver(self.reference, config_pin=self.pin, **self.metadata)

    def write(self, config):
        self.path.write_text(json.dumps(config))
        self.path.chmod(0o600)

    def resolve(self, **overrides):
        return self.resolver.resolve(overrides.get('reference', self.reference),
            provider=overrides.get('provider', 'jira'), config_version=overrides.get('version', 4))

    def test_real_reader_returns_private_independent_copies_without_network(self):
        with patch.object(atlassian, 'load_config', wraps=atlassian.load_config) as loader, patch.object(socket, 'socket', side_effect=AssertionError('no network')):
            private = self.resolve()
        loader.assert_called_once_with(self.path)
        self.assertIs(type(private), PrivateAtlassianConfig)
        self.assertEqual(private.private_copy(), self.config)
        changed = private.private_copy()
        changed['api_token'] = 'changed-local-copy'
        changed['future']['preserved'] = False
        self.assertEqual(private.private_copy(), self.config)
        for value in (self.pin, self.resolver, private):
            self.assertNotIn(self.config['api_token'], repr(value))
            self.assertNotIn(self.config['base_url'], repr(value))
            self.assertNotIn(str(self.path), repr(value))
            with self.assertRaises(TypeError):
                json.dumps(value)

    def test_wrong_reference_provider_or_version_is_refused_before_file_access(self):
        variants = [dict(reference={**self.reference, 'id': 'other'}),
                    dict(reference={**self.reference, 'ownerHubId': 'other'}),
                    dict(reference={**self.reference, 'revision': 5}),
                    dict(reference={**self.reference, 'path': str(self.path)}),
                    dict(provider='confluence'), dict(provider='github'), dict(version=5), dict(version=True)]
        with patch.object(atlassian, 'load_config') as loader:
            for variant in variants:
                with self.subTest(variant=variant), self.assertRaisesRegex(ContractError, 'integration_credential_refused'):
                    self.resolve(**variant)
        loader.assert_not_called()

    def test_config_changes_cannot_reuse_the_pin_even_in_a_new_resolver(self):
        for key, value in (('api_token', 'SYNTHETIC-ROTATED'), ('email', 'other@example.invalid'),
                           ('base_url', 'https://other.atlassian.example'), ('jira_project', 'OTHER'),
                           ('confluence_space', 'OTHER'), ('future', {'preserved': False})):
            with self.subTest(key=key):
                self.write({**self.config, key: value})
                resolver = AtlassianCredentialResolver(self.reference, config_pin=self.pin, **self.metadata)
                with self.assertRaisesRegex(ContractError, 'integration_credential_changed') as raised:
                    resolver.resolve(self.reference, provider='jira', config_version=4)
                self.assertNotIn(value if isinstance(value, str) else 'preserved', str(raised.exception))

    def test_identical_replacement_or_permission_change_also_requires_enrollment(self):
        replacement = self.directory / 'replacement'
        replacement.write_bytes(self.path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        with self.assertRaisesRegex(ContractError, 'integration_credential_changed'):
            self.resolve()
        self.path.chmod(0o400)
        with self.assertRaises(ContractError):
            self.resolve()

    def test_missing_unsafe_linked_or_oversized_files_fail_without_credentials(self):
        scenarios = ('missing', 'symlink', 'hardlink', 'mode', 'oversized', 'invalid-json')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                if self.path.is_symlink() or self.path.exists():
                    self.path.unlink()
                self.write(self.config)
                if scenario == 'missing':
                    self.path.unlink()
                elif scenario == 'symlink':
                    target = self.directory / 'secret-target'
                    target.write_bytes(self.path.read_bytes())
                    target.chmod(0o600)
                    self.path.unlink()
                    self.path.symlink_to(target)
                elif scenario == 'hardlink':
                    os.link(self.path, self.directory / 'extra-link')
                elif scenario == 'mode':
                    self.path.chmod(0o644)
                elif scenario == 'oversized':
                    self.path.write_text(self.config['api_token'] * 10000)
                else:
                    self.path.write_text('{"api_token":' + self.config['api_token'])
                with self.assertRaisesRegex(ContractError, 'integration_credential_unavailable') as raised:
                    self.resolve()
                self.assertNotIn(self.config['api_token'], str(raised.exception))

    def test_parent_symlink_and_directory_access_changes_are_refused(self):
        alias = self.directory / 'alias'
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ContractError, 'integration_credential_unavailable'):
            pin_atlassian_config(self.reference, **{**self.metadata, 'config_path': alias / self.path.name})
        self.directory.chmod(0o777)
        try:
            with self.assertRaisesRegex(ContractError, 'integration_credential_unavailable'):
                self.resolve()
        finally:
            self.directory.chmod(0o700)

    def test_change_during_actual_read_is_refused(self):
        original = atlassian.load_config
        def changed(path):
            config = original(path)
            self.write({**self.config, 'api_token': 'SYNTHETIC-ROTATED'})
            return config
        with patch.object(atlassian, 'load_config', side_effect=changed):
            with self.assertRaisesRegex(ContractError, 'integration_credential_changed'):
                self.resolve()

    def test_host_metadata_must_match_pin_and_common_reference(self):
        variants = [dict(provider='github'), dict(config_path='caller/path'),
                    dict(config_path=Path('relative')), dict(site_url='http://fixture.example'),
                    dict(site_url='https://other.example'), dict(config_version=5), dict(config_version=True)]
        for override in variants:
            with self.subTest(override=override), self.assertRaisesRegex(ContractError, 'integration_credential_configuration'):
                AtlassianCredentialResolver(self.reference, config_pin=self.pin, **{**self.metadata, **override})
        with self.assertRaisesRegex(ContractError, 'integration_credential_site_mismatch'):
            pin_atlassian_config(self.reference, **{**self.metadata, 'site_url': 'https://other.example'})
        with self.assertRaises(FrozenInstanceError):
            self.resolver._binding = ()

    def test_both_atlassian_providers_and_server_config_use_the_actual_reader(self):
        server = {**self.config, 'deployment': 'server'}
        server.pop('email')
        self.write(server)
        reference = {**self.reference, 'id': 'confluence-account'}
        metadata = {**self.metadata, 'provider': 'confluence'}
        pin = pin_atlassian_config(reference, **metadata)
        resolver = AtlassianCredentialResolver(reference, config_pin=pin, **metadata)
        self.assertEqual(resolver.resolve(reference, provider='confluence', config_version=4).private_copy(), server)

    def test_untrusted_reader_error_is_never_public(self):
        with patch.object(atlassian, 'load_config', side_effect=RuntimeError(self.config['api_token'])):
            with self.assertRaises(ContractError) as raised:
                self.resolve()
        self.assertEqual(str(raised.exception), 'integration_credential_unavailable')


if __name__ == '__main__':
    unittest.main()
