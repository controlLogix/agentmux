"""Pure Claude Code hook ownership and preservation checks."""
import json
import unittest

from dashboard.claude_hook_registration import prepare_claude_hook_registration
from dashboard.resource_registration import RegistrationConflict
from hub.installed_client_admission import STABLE_FRONTEND


class ClaudeHookRegistration(unittest.TestCase):
    configuration = '/private/claude/settings.json'
    selection = '/private/enrollment selection.json'
    first = '1' * 64
    second = '2' * 64

    def plan(self, raw, installation=None, **options):
        installation = self.first if installation is None else installation
        return prepare_claude_hook_registration(raw, installation_id=installation,
            configuration_path=self.configuration, command=STABLE_FRONTEND,
            arguments=('claude-code-hook', '--client-installation', installation,
                       '--selection', self.selection), **options)

    def test_add_update_remove_restore_preserve_unrelated_hook_arrays_and_numbers(self):
        raw = (b'{"large":1e9999,"hooks":{"SessionStart":[{"matcher":"clear",'
               b'"hooks":[{"type":"command","command":"/unrelated","args":[]}]}],'
               b'"Stop":[{"hooks":[]}]},"secret":"PRIVATE_SENTINEL"}\n')
        added = self.plan(raw)
        value = json.loads(added.after, parse_float=str)
        self.assertEqual(value['large'], '1e9999')
        self.assertEqual(value['secret'], 'PRIVATE_SENTINEL')
        self.assertEqual(value['hooks']['SessionStart'][0]['matcher'], 'clear')
        self.assertEqual(value['hooks']['Stop'], [{'hooks': []}])
        self.assertIn(b'1e9999', added.after)
        self.assertEqual(value['hooks']['SessionStart'][1]['hooks'][0]['args'],
            ['claude-code-hook', '--client-installation', self.first, '--selection', self.selection])

        updated = self.plan(added.after, installation=self.second, owned=added.ownership)
        self.assertEqual(updated.outcome, 'updated')
        self.assertEqual(json.loads(updated.ownership.group_json)['hooks'][0]['args'][2], self.second)
        removed = self.plan(updated.after, installation=self.second, owned=updated.ownership, remove=True)
        self.assertEqual(json.loads(removed.after)['hooks']['SessionStart'],
                         value['hooks']['SessionStart'][:1])
        restored = self.plan(removed.after, installation=self.second, restore=updated.ownership)
        self.assertEqual(restored.outcome, 'restored')
        self.assertEqual(json.loads(restored.after), json.loads(updated.after))

    def test_owned_container_cleanup_does_not_remove_unrelated_containers(self):
        added = self.plan(None)
        self.assertTrue(added.ownership.created_hooks)
        self.assertTrue(added.ownership.created_event)
        removed = self.plan(added.after, owned=added.ownership, remove=True)
        self.assertEqual(removed.after, b'{}\n')

        existing = self.plan(b'{"hooks":{}}\n')
        removed = self.plan(existing.after, owned=existing.ownership, remove=True)
        self.assertEqual(removed.after, b'{"hooks":{}}\n')

    def test_unowned_duplicate_changed_owner_and_invalid_shapes_refuse(self):
        added = self.plan(b'{}\n')
        with self.assertRaisesRegex(RegistrationConflict, '^registration_not_owned$'):
            self.plan(added.after)
        unowned = json.loads(added.after)
        unowned['hooks']['SessionStart'][0]['hooks'][0]['timeout'] = 30
        with self.assertRaisesRegex(RegistrationConflict, '^registration_not_owned$'):
            self.plan((json.dumps(unowned) + '\n').encode())
        changed = json.loads(added.after)
        changed['hooks']['SessionStart'][0]['matcher'] = 'startup'
        with self.assertRaisesRegex(RegistrationConflict, '^registration_changed$'):
            self.plan((json.dumps(changed) + '\n').encode(), owned=added.ownership)
        for raw in (b'{"hooks":[]}\n', b'{"hooks":{"SessionStart":{}}}\n',
                    b'{"hooks":{},"hooks":{}}\n'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(RegistrationConflict, '^configuration_invalid$'):
                    self.plan(raw)


if __name__ == '__main__':
    unittest.main()
