"""Definition command shape checks; these do not establish edit authority."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdk' / 'python'))
from agentmux_contracts import ContractError, validate


class DefinitionContracts(unittest.TestCase):
    def payload(self, action='save'):
        value = {'definitionId': 'definition_one', 'scope': 'repo',
                 'name': 'worker-one', 'expectedChecksum': 'sha256:' + 'a' * 64}
        if action == 'save':
            value['definition'] = {'description': 'Review assigned changes',
                                   'persona': 'Check the diff.\nExplain findings.'}
        return value

    def rejected(self, action, value):
        with self.assertRaises(ContractError):
            validate('definition-' + action, value)

    def test_save_update_create_and_drop_shapes(self):
        for action in ('save', 'drop'):
            self.assertIsNone(validate('definition-' + action, self.payload(action)))
        create = self.payload()
        create['expectedChecksum'] = None
        self.assertIsNone(validate('definition-save', create))
        # The owner distinguishes first creation from recreation at a tombstone revision.
        drop = self.payload('drop')
        drop['expectedChecksum'] = None
        self.rejected('drop', drop)

    def test_no_authority_path_or_version_fields_in_payload(self):
        for action in ('save', 'drop'):
            for field, value in [('actor', 'admin'), ('path', '/tmp/worker.md'),
                                 ('expectedVersion', 0), ('grantRef', {})]:
                with self.subTest(action=action, field=field):
                    payload = self.payload(action)
                    payload[field] = value
                    self.rejected(action, payload)
        for field in ('actor', 'name', 'path', 'unknown'):
            payload = self.payload()
            payload['definition'][field] = 'untrusted'
            self.rejected('save', payload)

    def test_closed_names_scope_and_checksum(self):
        for action in ('save', 'drop'):
            for field, value in [('name', '../worker'), ('name', 'Worker'),
                                 ('scope', 'claude'), ('definitionId', '../id'),
                                 ('expectedChecksum', 'stale')]:
                with self.subTest(action=action, field=field):
                    payload = self.payload(action)
                    payload[field] = value
                    self.rejected(action, payload)
            for field in self.payload(action):
                payload = self.payload(action)
                del payload[field]
                self.rejected(action, payload)

    def test_existing_definition_field_constraints(self):
        payload = self.payload()
        payload['definition'].update(cli='claude', model=None, auth=None,
            posture='workspace-write', tools=['Read'], tools_deny=['Bash'],
            role='worker', capabilities=['review'], worktree='per-member', max_instances=8)
        self.assertIsNone(validate('definition-save', payload))
        for field, invalid in [('description', ' '), ('cli', 'a/b'),
                               ('tools', ['Read,Write']), ('tools_deny', [' ']),
                               ('role', 'admin'), ('posture', 'root'),
                               ('capabilities', ['Tag']), ('worktree', 'shared'),
                               ('max_instances', True), ('max_instances', 9),
                               ('persona', 'x' * 4097)]:
            with self.subTest(field=field, invalid=invalid):
                changed = copy.deepcopy(payload)
                changed['definition'][field] = invalid
                self.rejected('save', changed)

    def test_effect_commands_are_closed_and_preserve_original_identity(self):
        for action in ('effect-query', 'effect-complete', 'effect-retry'):
            value = {'definitionId': 'definition-one', 'name': 'worker', 'scope': 'repo',
                     'originalOperationId': 'save-one', 'originalPayloadDigest': 'sha256:' + 'a' * 64,
                     'effectId': 'effect-one'}
            if action != 'effect-query':
                value['attemptOperationId'] = 'attempt-one'
            validate('definition-' + action, value)
            for field in ('status', 'actor', 'path', 'evidence'):
                changed = dict(value, **{field: 'untrusted'})
                self.rejected(action, changed)

    def test_catalog_receipt_pointer_is_optional_nullable_and_closed(self):
        item = {'definitionId': 'definition-one', 'name': 'worker', 'targetScope': 'repo',
                'version': 2, 'checksum': None, 'deleted': True, 'contentRef': None}
        catalog = {'schemaVersion': '1.0.0', 'scope': {'organizationId': 'org-one',
            'projectId': 'project-one', 'workspaceId': None}, 'definitions': [item]}
        validate('definition-catalog-state', catalog)
        for pointer in (None, {'operationId': 'receipt-one', 'payloadDigest': 'sha256:' + 'a' * 64}):
            item['effectReceiptRef'] = pointer
            validate('definition-catalog-state', catalog)
        item['effectReceiptRef']['status'] = 'applied'
        with self.assertRaises(ContractError):
            validate('definition-catalog-state', catalog)

    def test_registry_selects_fixed_owner(self):
        registry = json.loads((ROOT / 'contracts/v1/registry.json').read_text())
        for action in ('save', 'drop', 'effect-query', 'effect-complete', 'effect-retry'):
            name = 'definition-' + action
            self.assertEqual(registry['contracts'][name], {
                'major': 1, 'kind': 'command', 'payloadSchema': name,
                'destinationServiceId': 'definition-owner'})


if __name__ == '__main__':
    unittest.main()
