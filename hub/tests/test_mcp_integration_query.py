"""Fixed enrolled query boundary; no broker or external provider is contacted."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hub.client_launch_coordinator import result
from hub.fed import mcp


class McpIntegrationQuery(unittest.TestCase):
    def setUp(self):
        self.started = result('ensure', 'observed')
        self.arguments = {'operationId': 'query-one', 'expectedVersion': 1}
        self.receipt = {'operationId': 'query-one', 'originalOperationId': 'intent-one',
            'originalPayloadDigest': 'sha256:' + 'a' * 64, 'sequence': 1,
            'attemptOperationId': None, 'phase': 'intent-committed'}
        self.session = SimpleNamespace(query_enabled=lambda: True,
            query_effect=Mock(return_value=self.receipt))

    def request(self, arguments=None):
        return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'agentmux_integration_effect_query',
            'arguments': self.arguments if arguments is None else arguments}}

    def handle(self, request):
        with patch.object(mcp.cli, 'call') as legacy, patch.object(mcp, 'fed_tools') as registry:
            response = mcp.handle(request, dict(mcp.CORE), startup_result=self.started,
                                  application_session=self.session)
        legacy.assert_not_called()
        registry.assert_not_called()
        return response

    def test_only_enrolled_query_advertised_and_dispatches_closed_arguments(self):
        response = self.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        self.assertEqual([tool['name'] for tool in response['tools']],
                         ['agentmux_startup_status', 'agentmux_integration_effect_query'])
        schema = response['tools'][1]['inputSchema']
        self.assertFalse(schema['additionalProperties'])
        self.assertEqual(set(schema['properties']), {'operationId', 'expectedVersion'})
        self.assertEqual(self.handle(self.request())['structuredContent'], self.receipt)
        self.session.query_effect.assert_called_once_with(self.arguments)
        self.assertEqual(self.started.public['applicationAccess'], 'unavailable')

    def test_other_authority_and_malformed_arguments_never_dispatch(self):
        for arguments in ({}, {**self.arguments, 'subject': 'PRIVATE'},
                {**self.arguments, 'grantRef': {}}, {**self.arguments, 'expectedVersion': True},
                {**self.arguments, 'expectedVersion': 9007199254740992},
                {**self.arguments, 'operationId': 'INVALID'}):
            with self.subTest(arguments=arguments), self.assertRaises(mcp.ProtocolError) as failure:
                self.handle(self.request(arguments))
            self.assertEqual(failure.exception.code, -32602)
        self.session.query_effect.assert_not_called()

    def test_unenrolled_route_and_notifications_never_dispatch(self):
        self.session.query_enabled = lambda: False
        response = self.handle(self.request())
        self.assertTrue(response['isError'])
        listing = self.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        self.assertEqual(len(listing['tools']), 1)
        notification = self.request()
        notification.pop('id')
        self.assertIsNone(self.handle(notification))
        self.session.query_effect.assert_not_called()

    def test_private_failure_keeps_protocol_clean_and_next_status_available(self):
        self.session.query_effect.side_effect = OSError('PRIVATE_SENTINEL')
        self.session.status = lambda: {'state': 'verified', 'hubId': 'hub-one'}
        status = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                  'params': {'name': 'agentmux_startup_status'}}
        output = io.StringIO()
        mcp.main(io.StringIO(json.dumps(self.request()) + '\n' + json.dumps(status) + '\n'),
                 output, startup_result=self.started, application_session=self.session)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(replies), 2)
        self.assertTrue(replies[0]['result']['isError'])
        self.assertFalse(replies[1]['result']['isError'])
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())

    def test_terminal_login_tools_use_only_opaque_attempt_and_session_ids(self):
        attempt = 'oidc_attempt_' + 'a' * 32
        session = 'oidc_session_' + 'b' * 32
        self.session.oidc_terminal_enabled = lambda: True
        self.session.oidc_terminal_start = Mock(return_value={
            'attemptId': attempt, 'userCode': 'ABCD-EFGH',
            'verificationUri': 'https://identity.example/device'})
        self.session.oidc_terminal_status = Mock(return_value={
            'attemptId': attempt, 'outcome': 'approved', 'sessionId': session})
        self.session.oidc_terminal_logout = Mock(return_value={
            'sessionId': session, 'outcome': 'closed'})
        listing = self.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        self.assertEqual([tool['name'] for tool in listing['tools'][:4]], [
            'agentmux_startup_status', 'agentmux_oidc_terminal_start',
            'agentmux_oidc_terminal_status', 'agentmux_oidc_terminal_logout'])
        calls = [
            ('agentmux_oidc_terminal_start', {}, 'userCode'),
            ('agentmux_oidc_terminal_status', {'attemptId': attempt}, 'sessionId'),
            ('agentmux_oidc_terminal_logout', {'sessionId': session}, 'outcome')]
        for name, arguments, field in calls:
            response = self.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                'params': {'name': name, 'arguments': arguments}})
            self.assertIn(field, response['structuredContent'])
        self.session.oidc_terminal_start.assert_called_once_with()
        self.session.oidc_terminal_status.assert_called_once_with(attempt)
        self.session.oidc_terminal_logout.assert_called_once_with(session)

    def test_terminal_transport_failure_is_unconfirmed_not_invalid_arguments(self):
        from hub.client_launch_session import ApplicationSessionFailure
        self.session.oidc_terminal_enabled = lambda: True
        self.session.oidc_terminal_start = Mock(
            side_effect=ApplicationSessionFailure(self.session))
        response = self.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
            'params': {'name': 'agentmux_oidc_terminal_start', 'arguments': {}}})
        self.assertTrue(response['isError'])
        self.assertIn('outcome is unconfirmed', response['content'][0]['text'])
