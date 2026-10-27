"""Owner-supported retirement of a repository definitions fence (AMUX-728 review item 6)."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'taskmgmt')]

import ccboard
import definition_retirement
from definition_service import DefinitionScope, DefinitionService

HOLD = """
import sys, time
from pathlib import Path
sys.path[:0] = [sys.argv[5], sys.argv[6]]
from definition_service import DefinitionScope, DefinitionService
service = DefinitionService(DefinitionScope(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), 'project'))
service.claim_retained_writer('repo', sys.argv[4].encode())
print('claimed', flush=True)
time.sleep(60)
"""


def owner_key(hub):
    return json.dumps({'domain': 'definitions', 'entityId': 'local_catalog', 'hubId': hub,
                       'scope': {'organizationId': 'org', 'projectId': 'project', 'workspaceId': None}},
                      sort_keys=True, separators=(',', ':'))


class DefinitionRetirementTests(unittest.TestCase):
    def setUp(self):
        base = Path(tempfile.mkdtemp(prefix='amux-retire.')).resolve()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', str(base)]))
        self.repo, self.home, self.global_root = base / 'repo', base / 'home', base / 'global'
        for path in (self.repo, self.home, self.global_root):
            path.mkdir()
        self.service = DefinitionService(DefinitionScope(self.repo, self.home, self.global_root, 'project'))
        self.fence = self.repo / '.agentmux/agents/.owner-fence'

    def hold(self, hub):
        """Run a live retained owner in another process, as an enrolled host does."""
        process = subprocess.Popen([sys.executable, '-c', HOLD, str(self.repo), str(self.home), str(self.global_root),
                                    owner_key(hub), str(HERE), str(HERE.parent / 'taskmgmt')],
                                   stdout=subprocess.PIPE, text=True)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.assertEqual(process.stdout.readline().strip(), 'claimed')
        return process

    def test_stopped_owner_is_retired_and_the_next_owner_takes_over(self):
        owner = self.hold('hub_old')
        # A live owner in another process keeps its fence.
        with self.assertRaisesRegex(ccboard.Refused, 'definition_owner_running'):
            self.service.retire_retained_writer('repo', 'hub_old', apply=True)
        self.assertEqual(self.fence.read_bytes(), owner_key('hub_old').encode())
        owner.kill()
        owner.wait()
        self.assertEqual(self.service.retire_retained_writer('repo', 'hub_old'),
                         {'outcome': 'retirable', 'hubId': 'hub_old'})
        self.assertEqual(self.fence.read_bytes(), owner_key('hub_old').encode())
        self.assertEqual(self.service.retire_retained_writer('repo', 'hub_old', apply=True),
                         {'outcome': 'retired', 'hubId': 'hub_old'})
        self.assertEqual(self.service.retire_retained_writer('repo', 'hub_old', apply=True),
                         {'outcome': 'already_retired', 'hubId': 'hub_old'})
        # Legacy writes stay denied after retirement.
        with self.assertRaises(ccboard.Refused):
            self.service.legacy_save(None, {'name': 'other', 'scope': 'repo'})
        self.hold('hub_new')
        self.assertEqual(self.fence.read_bytes(), owner_key('hub_new').encode())
        self.assertEqual(oct(self.fence.stat().st_mode & 0o777), '0o600')

    def test_fence_of_another_hub_or_no_fence_is_refused(self):
        with self.assertRaisesRegex(ccboard.Refused, 'definition_owner_fence_absent'):
            self.service.retire_retained_writer('repo', 'hub_old', apply=True)
        owner = self.hold('hub_old')
        owner.kill()
        owner.wait()
        with self.assertRaisesRegex(ccboard.Refused, 'definition_owner_fence_mismatch'):
            self.service.retire_retained_writer('repo', 'hub_other', apply=True)
        self.assertEqual(self.fence.read_bytes(), owner_key('hub_old').encode())

    def test_second_live_owner_is_refused_while_the_first_holds_the_lease(self):
        self.hold('hub_old')
        process = subprocess.run([sys.executable, '-c', HOLD, str(self.repo), str(self.home), str(self.global_root),
                                  owner_key('hub_old'), str(HERE), str(HERE.parent / 'taskmgmt')],
                                 capture_output=True, text=True, timeout=30)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('another retained owner', process.stderr)

    def test_command_reports_only_closed_outcomes(self):
        owner = self.hold('hub_old')
        arguments = ['--repository-root', str(self.repo), '--hub-id', 'hub_old']
        with mock.patch('sys.stderr', new_callable=io.StringIO) as err:
            self.assertEqual(definition_retirement.main(arguments + ['--apply']), 1)
        self.assertEqual(json.loads(err.getvalue())['code'], 'definition_owner_running')
        owner.kill()
        owner.wait()
        for extra, outcome in (([], 'retirable'), (['--apply'], 'retired')):
            with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
                self.assertEqual(definition_retirement.main(arguments + extra), 0)
            self.assertEqual(json.loads(out.getvalue()), {'schemaVersion': '1.0.0',
                'kind': 'definitions-owner-retirement', 'outcome': outcome, 'hubId': 'hub_old',
                'applied': extra == ['--apply']})
        for wrong in ([], ['--repository-root', 'relative', '--hub-id', 'hub_old'],
                      ['--repository-root', str(self.repo), '--hub-id', 'Bad Hub'],
                      arguments + ['--force']):
            with self.subTest(arguments=wrong), mock.patch('sys.stderr', new_callable=io.StringIO) as err:
                self.assertEqual(definition_retirement.main(wrong), 1)
                self.assertEqual(json.loads(err.getvalue())['code'], 'definitions_retirement_arguments_invalid')


if __name__ == '__main__':
    unittest.main()
