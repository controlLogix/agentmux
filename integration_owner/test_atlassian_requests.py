"""Pure request integration checks using synthetic credentials and content."""
import hashlib
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from integration_owner.atlassian_requests import prepare_atlassian_request
from integration_owner.test_intent import payload
from taskmgmt.test_atlassian_safety import CLOUD, SERVER
from taskmgmt import atlassian


def with_content(action, target, data):
    raw = canonical_bytes(data)
    body = {**payload(), 'action': action, 'target': target, 'contentRef': {
        'artifactId': 'artifact-one', 'ownerHubId': 'hub-one',
        'storeRef': {'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1},
        'version': 'v-one', 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(),
        'bytes': len(raw), 'mediaType': 'application/vnd.agentmux.integration-content+json'}}
    return body, raw


class AtlassianRequests(unittest.TestCase):
    def test_transition_retains_exact_external_ids_and_never_opens_transport(self):
        with patch.object(atlassian.urllib.request, 'build_opener') as opener:
            prepared = prepare_atlassian_request(payload(), None, CLOUD)
        opener.assert_not_called()
        request = strict_loads(prepared.request)
        self.assertTrue(request['url'].endswith('/issue/AMUX-66/transitions'))
        self.assertEqual(request['body'], {'transition': {'id': '31'}})
        self.assertNotIn(CLOUD['api_token'].encode(), prepared.request)

    def test_comment_preserves_cloud_adf_and_server_text(self):
        proposal, raw = with_content('jira-comment', {'issueKey': 'AMUX-66'}, {'text': 'first\nsecond'})
        with patch.object(atlassian.urllib.request, 'build_opener') as opener:
            cloud = strict_loads(prepare_atlassian_request(proposal, raw, CLOUD).request)
            server = strict_loads(prepare_atlassian_request(proposal, raw, SERVER).request)
        opener.assert_not_called()
        self.assertEqual(cloud['body']['body']['type'], 'doc')
        self.assertEqual(server['body']['body'], 'first\nsecond')

    def test_confluence_update_never_looks_up_a_title_or_changes_page_identity(self):
        proposal, raw = with_content('confluence-update',
            {'spaceKey': 'DOCS', 'pageId': '42', 'expectedVersion': 7},
            {'title': 'Existing title', 'html': '<p>Approved content</p>'})
        with patch.object(atlassian, 'confluence_find') as lookup:
            prepared = prepare_atlassian_request(proposal, raw, CLOUD)
        lookup.assert_not_called()
        request = strict_loads(prepared.request)
        self.assertEqual(request['method'], 'PUT')
        self.assertTrue(request['url'].endswith('/content/42'))
        self.assertEqual(request['body']['version'], {'number': 8})

    def test_changed_selected_project_is_refused(self):
        proposal, raw = with_content('jira-create', {'projectKey': 'TEST', 'issueType': 'Task'},
            {'summary': 'Approved summary', 'description': '', 'labels': []})
        with self.assertRaisesRegex(ContractError, 'integration_config_target_changed'):
            prepare_atlassian_request(proposal, raw, {**CLOUD, 'jira_project': 'OTHER'})

    def test_changed_content_or_extra_secret_field_cannot_prepare(self):
        proposal, raw = with_content('jira-comment', {'issueKey': 'AMUX-66'}, {'text': 'Approved'})
        with self.assertRaisesRegex(ContractError, 'integration_content_digest_mismatch'):
            prepare_atlassian_request(proposal, raw + b' ', CLOUD)
        proposal, raw = with_content('jira-comment', {'issueKey': 'AMUX-66'},
                                    {'text': 'Approved', 'api_token': 'synthetic-private'})
        with self.assertRaises(ContractError):
            prepare_atlassian_request(proposal, raw, CLOUD)


if __name__ == '__main__':
    unittest.main()
