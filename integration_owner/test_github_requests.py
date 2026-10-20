"""Offline checks for fixed GitHub requests and exact content binding."""
from dataclasses import FrozenInstanceError
from hashlib import sha256
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads

from integration_owner.github_requests import prepare_github_request


def proposal(action='github-repo-create', target=None, raw=None):
    body = {
        'effectRef': {'id': 'effect-one', 'ownerHubId': 'hub-one', 'revision': 1},
        'credentialRef': {'id': 'credential-one', 'ownerHubId': 'hub-one', 'revision': 1},
        'action': action,
        'target': target if target is not None else {
            'owner': 'Exact-Owner', 'name': 'Exact_Repo.Name', 'visibility': 'private'},
        'contentRef': None,
    }
    if raw is not None:
        body['contentRef'] = {
            'artifactId': 'artifact-one', 'ownerHubId': 'hub-one',
            'storeRef': {'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1},
            'version': 'v-one', 'digest': 'sha256:' + sha256(raw).hexdigest(),
            'bytes': len(raw), 'mediaType': 'application/vnd.agentmux.integration-content+json',
        }
    return body


def issue(data=None, raw=None):
    if raw is None:
        raw = canonical_bytes(data if data is not None else {
            'title': 'Approved title', 'body': 'Approved body', 'labels': []})
    return proposal('github-issue-create', {'repository': 'Exact-Owner/Exact_Repo.Name'}, raw), raw


class GithubRequests(unittest.TestCase):
    def test_repo_target_and_each_visibility_are_explicit(self):
        for visibility in ('private', 'public', 'internal'):
            with self.subTest(visibility=visibility):
                body = proposal()
                body['target']['visibility'] = visibility
                prepared = prepare_github_request(body)
                self.assertEqual(prepared.action, 'github-repo-create')
                self.assertEqual(prepared.argv, ('repo', 'create',
                    'github.com/Exact-Owner/Exact_Repo.Name', '--' + visibility))
                self.assertEqual(strict_loads(prepared.target), body['target'])
                self.assertEqual(prepared.stdin, b'')

    def test_repo_content_preserves_text_and_cannot_add_flags(self):
        raw = canonical_bytes({'description': '--public  keep these spaces ',
                               'gitignore': 'C++', 'license': 'Apache-2.0'})
        prepared = prepare_github_request(proposal(raw=raw), raw)
        self.assertEqual(prepared.argv, ('repo', 'create',
            'github.com/Exact-Owner/Exact_Repo.Name', '--private',
            '--description=--public  keep these spaces ', '--gitignore=C++', '--license=Apache-2.0'))

    def test_each_repo_content_field_is_optional(self):
        for data in ({}, {'description': ''}, {'gitignore': ''}, {'license': ''}):
            with self.subTest(data=data):
                raw = canonical_bytes(data)
                self.assertEqual(prepare_github_request(proposal(raw=raw), raw).argv,
                                 prepare_github_request(proposal()).argv)

    def test_issue_keeps_leading_dashes_and_body_out_of_argv(self):
        data = {'title': '--web  keep these spaces ', 'body': '--private\r\n\tBody ☃',
                'labels': ['--web', 'bug', 'bug']}
        body, raw = issue(data)
        prepared = prepare_github_request(body, raw)
        self.assertEqual(prepared.argv, ('issue', 'create',
            '--repo=github.com/Exact-Owner/Exact_Repo.Name',
            '--title=--web  keep these spaces ', '--body-file', '-',
            '--label=--web', '--label=bug', '--label=bug'))
        self.assertEqual(prepared.stdin, data['body'].encode('utf-8'))
        self.assertEqual(strict_loads(prepared.target), body['target'])
        self.assertNotIn(data['body'], prepared.argv)

    def test_empty_issue_body_still_uses_stdin(self):
        body, raw = issue({'title': 'Title', 'body': '', 'labels': []})
        prepared = prepare_github_request(body, raw)
        self.assertEqual(prepared.argv[-2:], ('--body-file', '-'))
        self.assertEqual(prepared.stdin, b'')

    def test_maximum_unicode_issue_body_can_require_32000_stdin_bytes(self):
        body, raw = issue({'title': 'Title', 'body': '\U0001f600' * 8000, 'labels': []})
        prepared = prepare_github_request(body, raw)
        self.assertEqual(len(prepared.stdin), 32000)
        self.assertEqual(prepared.stdin, ('\U0001f600' * 8000).encode('utf-8'))

    def test_pretty_json_uses_the_exact_artifact_digest(self):
        raw = b'{ "title": "Title", "body": "", "labels": [] }\n'
        body, raw = issue(raw=raw)
        self.assertEqual(prepare_github_request(body, raw).stdin, b'')
        body['contentRef']['digest'] = 'sha256:' + sha256(canonical_bytes(strict_loads(raw))).hexdigest()
        with self.assertRaisesRegex(ContractError, 'integration_content_digest_mismatch'):
            prepare_github_request(body, raw)

    def test_size_and_digest_are_both_checked(self):
        body, raw = issue()
        for altered in (raw + b' ', raw.replace(b'Approved', b'Modified')):
            with self.subTest(altered=altered):
                with self.assertRaisesRegex(ContractError, 'integration_content_digest_mismatch'):
                    prepare_github_request(body, altered)
        body['contentRef']['bytes'] += 1
        with self.assertRaisesRegex(ContractError, 'integration_content_digest_mismatch'):
            prepare_github_request(body, raw)

    def test_content_must_match_its_presence_and_immutable_byte_type(self):
        body, raw = issue()
        for content in (None, raw.decode(), bytearray(raw), b'', b'x' * 60001):
            with self.subTest(content_type=type(content).__name__):
                with self.assertRaisesRegex(ContractError, 'integration_content_invalid'):
                    prepare_github_request(body, content)
        with self.assertRaisesRegex(ContractError, 'integration_content_unsupported'):
            prepare_github_request(proposal(), b'{}')
        body['contentRef'] = None
        with self.assertRaisesRegex(ContractError, 'integration_content_required'):
            prepare_github_request(body)

    def test_duplicate_fields_and_nonobjects_are_refused(self):
        for raw in (b'{"title":"one","title":"two","body":"","labels":[]}',
                    b'[]', b'null', b'{"title": NaN}', b'\xff'):
            with self.subTest(raw=raw):
                body, raw = issue(raw=raw)
                with self.assertRaises(ContractError):
                    prepare_github_request(body, raw)

    def test_no_actor_flags_or_secret_fields_can_enter_content(self):
        for extra in ('actor', 'confirm', 'argv', 'hostname', 'credential', 'token'):
            with self.subTest(extra=extra):
                raw = canonical_bytes({'description': 'Description', extra: 'private-value'})
                with self.assertRaises(ContractError) as error:
                    prepare_github_request(proposal(raw=raw), raw)
                self.assertNotIn('private-value', str(error.exception))
                body, raw = issue({'title': 'Title', 'body': '', 'labels': [], extra: 'private-value'})
                with self.assertRaises(ContractError):
                    prepare_github_request(body, raw)
        body = proposal()
        body['actor'] = 'caller'
        with self.assertRaises(ContractError):
            prepare_github_request(body)

    def test_target_changes_cannot_supply_flags_or_another_host(self):
        targets = ({'owner': '-owner', 'name': 'Repo', 'visibility': 'private'},
                   {'owner': 'Owner', 'name': '../Repo', 'visibility': 'private'},
                   {'owner': 'Owner', 'name': 'Repo', 'visibility': '--clone'},
                   {'owner': 'github.example/Owner', 'name': 'Repo', 'visibility': 'private'})
        for target in targets:
            with self.subTest(target=target):
                with self.assertRaises(ContractError):
                    prepare_github_request(proposal(target=target))
        for repository in ('github.example/Owner/Repo', '-Owner/Repo', 'Owner/..', 'Owner/Repo?x'):
            with self.subTest(repository=repository):
                body, raw = issue()
                body['target']['repository'] = repository
                with self.assertRaises(ContractError):
                    prepare_github_request(body, raw)

    def test_repo_text_and_template_bounds_are_checked_without_truncation(self):
        invalid = ({'description': 'x' * 351}, {'description': 'line\nbreak'},
                   {'description': '\x1b[31m'}, {'description': 4},
                   {'gitignore': '--clone'}, {'gitignore': 'x' * 41},
                   {'gitignore': None}, {'license': '-web'}, {'license': 'x' * 41},
                   {'license': ['MIT']})
        for data in invalid:
            with self.subTest(data=data):
                raw = canonical_bytes(data)
                with self.assertRaisesRegex(ContractError, 'integration_content_invalid'):
                    prepare_github_request(proposal(raw=raw), raw)
        raw = canonical_bytes({'description': 'x' * 350})
        self.assertIn('--description=' + 'x' * 350,
                      prepare_github_request(proposal(raw=raw), raw).argv)

    def test_issue_shape_and_bounds_are_checked_without_truncation(self):
        defaults = {'title': 'Title', 'body': '', 'labels': []}
        invalid = ({'title': ''}, {'title': '  '}, {'title': 'x' * 251},
                   {'title': 'line\nbreak'}, {'title': '\x85'}, {'title': 3},
                   {'body': 'x' * 8001}, {'body': '\x00'}, {'body': None},
                   {'labels': 'bug'}, {'labels': ['bug'] * 11},
                   {'labels': [None]}, {'labels': ['bug,enhancement']},
                   {'labels': ['x' * 51]}, {'labels': ['']})
        for changes in invalid:
            with self.subTest(changes=changes):
                body, raw = issue({**defaults, **changes})
                with self.assertRaisesRegex(ContractError, 'integration_content_invalid'):
                    prepare_github_request(body, raw)
        body, raw = issue({'title': 'x' * 250, 'body': 'x' * 8000, 'labels': ['x' * 50] * 10})
        prepared = prepare_github_request(body, raw)
        self.assertEqual(len(prepared.stdin), 8000)
        self.assertIn('--title=' + 'x' * 250, prepared.argv)
        body, raw = issue({'title': 'Title', 'body': ''})
        with self.assertRaisesRegex(ContractError, 'integration_shape_invalid'):
            prepare_github_request(body, raw)

    def test_other_integration_actions_are_refused(self):
        body = proposal('jira-transition', {'issueKey': 'AMUX-66', 'transitionId': '31'})
        with self.assertRaisesRegex(ContractError, 'integration_action_unsupported'):
            prepare_github_request(body)

    def test_prepared_request_is_immutable_and_repr_hides_content(self):
        body, raw = issue({'title': 'Private title', 'body': 'Private body', 'labels': ['private']})
        prepared = prepare_github_request(body, raw)
        body['target']['repository'] = 'Other/Repo'
        self.assertEqual(strict_loads(prepared.target), {'repository': 'Exact-Owner/Exact_Repo.Name'})
        self.assertIsInstance(prepared.argv, tuple)
        self.assertIsInstance(prepared.stdin, bytes)
        with self.assertRaises(FrozenInstanceError):
            prepared.stdin = b'changed'
        self.assertEqual(repr(prepared), '<PreparedGithubRequest private; no external dispatch>')
        self.assertNotIn(b'credential-one', prepared.target)
        self.assertNotIn('credential-one', prepared.argv)

    def test_preparation_does_not_open_files_or_start_external_work(self):
        body, raw = issue()
        with patch('builtins.open', side_effect=AssertionError('file access')), \
                patch('subprocess.run', side_effect=AssertionError('process start')), \
                patch('subprocess.Popen', side_effect=AssertionError('process start')), \
                patch('socket.socket', side_effect=AssertionError('network access')):
            prepared = prepare_github_request(body, raw)
        self.assertEqual(prepared.action, 'github-issue-create')


if __name__ == '__main__':
    unittest.main()
