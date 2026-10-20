"""Optional profile display metadata never changes the legacy authority contract."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, ValidationError


class ProfileContextContract(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'contracts/v1/schemas/legacy-plugin-contribution.schema.json'
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        self.validator = Draft202012Validator(schema)
        self.descriptor = {'schemaVersion':'1.0.0', 'kind':'legacy-federation-plugin',
            'plugin':'work', 'trust':'administrator-installed-python', 'context':'legacy-federation',
            'hooks':['start','on_connect','on_tick','on_envelope','on_local_event','on_revoke'],
            'envelopeTypes':[], 'tablePrefix':'p_work_', 'tableStatements':[], 'panelId':'work', 'commands':[]}

    def test_legacy_descriptor_omits_context_without_inventing_values(self):
        self.validator.validate(self.descriptor)
        self.assertNotIn('profileContext', self.descriptor)

    def test_only_supplied_environment_or_project_is_preserved(self):
        for context in ({'environment':'Development'}, {'project':'My Project'},
                        {'environment':'Production', 'project':'My Project'}):
            value = dict(self.descriptor, profileContext=copy.deepcopy(context))
            self.validator.validate(value)
            self.assertEqual(value['profileContext'], context)

    def test_empty_null_or_non_display_values_are_refused(self):
        for context in (None, {}, {'environment':None}, {'project':''}, {'project':'   '},
                        {'environment':' leading'}, {'project':'trailing '}, {'project':'x\n'},
                        {'project':'x\u0085y'}, {'environment':'x\u2028y'}, {'project':12},
                        {'project':'x'*129}, {'environment':'dev', 'project':None}):
            with self.subTest(context=context), self.assertRaises(ValidationError):
                self.validator.validate(dict(self.descriptor, profileContext=context))

    def test_authority_fields_and_unknown_keys_are_refused(self):
        for field in ('projectId', 'scope', 'grantRef', 'workspace', 'user'):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.validator.validate(dict(self.descriptor,
                    profileContext={'environment':'dev', field:'injected'}))


class NativeProfileContextContract(ProfileContextContract):
    schema_directory = 'contracts/v1/schemas'

    def setUp(self):
        from referencing import Registry, Resource
        root = Path(__file__).resolve().parents[1]
        directory = root / self.schema_directory
        schemas = [json.loads(path.read_text()) for path in directory.glob('*.schema.json')]
        registry = Registry().with_resources((value['$id'], Resource.from_contents(value)) for value in schemas)
        schema = json.loads((directory / 'plugin-context.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        self.validator = Draft202012Validator(schema, registry=registry)
        self.descriptor = json.loads((root / 'sdk/typescript/test-examples.json').read_text())['plugin-context']

    def test_native_copies_and_legacy_metadata_rules_match(self):
        root = Path(__file__).resolve().parents[1]
        shared = json.loads((root / 'contracts/v1/schemas/plugin-context.schema.json').read_text())
        native = json.loads((root / 'platform/plugins/schemas/plugin-context.schema.json').read_text())
        legacy = json.loads((root / 'contracts/v1/schemas/legacy-plugin-contribution.schema.json').read_text())
        self.assertEqual(shared, native)
        self.assertNotIn('profileContext', shared['required'])
        self.assertEqual(shared['properties']['profileContext'], legacy['properties']['profileContext'])
        self.assertEqual(shared['$defs']['profileDisplayValue'], legacy['$defs']['profileDisplayValue'])


class EmbeddedNativeProfileContextContract(NativeProfileContextContract):
    schema_directory = 'platform/plugins/schemas'
