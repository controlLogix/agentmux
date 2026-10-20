"""First-party code calls reuse one negotiated operation ID on transport loss."""
import json
import unittest
from unittest.mock import Mock, patch

from hub import cli


class Socket:
    def __init__(self, response=None, error=None, on_receive=None):
        self.response = json.dumps(response or {'ok': True, 'result': {'id': 'original'}}).encode() + b'\n'
        self.error, self.on_receive = error, on_receive
        self.packets, self.timeouts = [], []
        self.closed = False

    def sendall(self, raw):
        self.packets.append(json.loads(raw))

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        if self.on_receive:
            self.on_receive()
        if self.error:
            raise self.error
        return self.response

    def close(self):
        self.closed = True


class CodeOperationCliTests(unittest.TestCase):
    def setUp(self):
        timer = patch.object(cli, 'validate_callback', return_value=False)
        timer.start()
        self.addCleanup(timer.stop)

    def registry(self, qualified=True, verb='fed_code_share'):
        return Socket({'ok': True, 'result': [{'verb': verb, 'operationIds': qualified}]})

    def test_qualified_negotiation_generates_once_and_retries_identical_packet(self):
        registry, lost, recovered = self.registry(), Socket(error=ConnectionResetError()), Socket()
        with patch.object(cli, 'connect', side_effect=[(item, False) for item in (registry, lost, recovered)]) as connect, \
                patch.object(cli.secrets, 'token_hex', return_value='a' * 48) as generate:
            result = cli.call('fed_code_share', {'repo': 'falcon', 'note': 'Original request'})
        self.assertTrue(result['ok'])
        self.assertEqual(registry.packets[0]['verb'], 'fed_verbs')
        self.assertEqual(lost.packets, recovered.packets)
        self.assertEqual(recovered.packets[0]['operationId'], 'code_' + 'a' * 48)
        generate.assert_called_once_with(24)
        self.assertEqual(connect.call_count, 3)
        self.assertTrue(all(item.closed for item in (registry, lost, recovered)))

    def test_deliberate_identical_new_call_gets_a_new_operation_id(self):
        sockets = [self.registry(), Socket(), self.registry(), Socket()]
        with patch.object(cli, 'connect', side_effect=[(item, False) for item in sockets]), \
                patch.object(cli.secrets, 'token_hex', side_effect=['a' * 48, 'b' * 48]):
            cli.call('fed_code_share', {'repo': 'falcon'})
            cli.call('fed_code_share', {'repo': 'falcon'})
        self.assertNotEqual(sockets[1].packets[0]['operationId'], sockets[3].packets[0]['operationId'])
        self.assertEqual(sockets[1].packets[0]['args'], sockets[3].packets[0]['args'])

    def test_explicit_recovery_id_is_top_level_and_not_replaced(self):
        registry, lost, recovered = self.registry(verb='fed_code_fetch'), Socket(error=BrokenPipeError()), Socket()
        arguments = {'id': 'original-share', 'operation_id': 'recover-original'}
        with patch.object(cli, 'connect', side_effect=[(item, False) for item in (registry, lost, recovered)]), \
                patch.object(cli.secrets, 'token_hex') as generate:
            cli.call('fed_code_fetch', arguments)
        self.assertEqual(recovered.packets[0]['operationId'], 'recover-original')
        self.assertEqual(recovered.packets[0]['args'], {'id': 'original-share'})
        self.assertEqual(arguments['operation_id'], 'recover-original')
        self.assertEqual(lost.packets, recovered.packets)
        generate.assert_not_called()

    def test_unqualified_hub_keeps_legacy_no_id_and_does_not_retry(self):
        registry, lost = self.registry(False), Socket(error=ConnectionResetError())
        with patch.object(cli, 'connect', side_effect=[(registry, False), (lost, False)]) as connect, \
                patch.object(cli.secrets, 'token_hex') as generate:
            with self.assertRaises(cli.Fail):
                cli.call('fed_code_share', {'repo': 'falcon'})
        self.assertNotIn('operationId', lost.packets[0])
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(lost.closed)
        generate.assert_not_called()

    def test_application_refusal_is_not_a_transport_retry(self):
        registry, refused = self.registry(), Socket({'ok': False, 'error': 'Current grant refused'})
        with patch.object(cli, 'connect', side_effect=[(registry, False), (refused, False)]) as connect:
            with self.assertRaises(cli.Fail) as error:
                cli.call('fed_code_share', {'repo': 'falcon', 'operation_id': 'refused-original'})
        self.assertIn('refused-original', str(error.exception))
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(refused.closed)

    def test_one_deadline_stops_transport_retry_and_closes_original_socket(self):
        clock = [10.0]
        registry = self.registry()
        def expired():
            clock[0] = 100.0
        lost = Socket(error=TimeoutError(), on_receive=expired)
        with patch.object(cli, 'connect', side_effect=[(registry, False), (lost, False)]) as connect, \
                patch.object(cli.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(cli.Fail) as error:
                cli.call('fed_code_share', {'repo': 'falcon', 'operation_id': 'timed-out-original'}, timeout=30)
        self.assertIn('--operation-id timed-out-original', str(error.exception))
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(lost.closed)

    def test_tcp_retry_may_refresh_only_credential_bytes(self):
        registry, lost, recovered = self.registry(), Socket(error=ConnectionResetError()), Socket()
        with patch.object(cli, 'connect', side_effect=[(registry, False), (lost, True), (recovered, True)]), \
                patch.object(cli, 'tcp_token', side_effect=['old-test-credential', 'new-test-credential']):
            cli.call('fed_code_share', {'repo': 'falcon', 'operation_id': 'same-principal'})
        first, second = dict(lost.packets[0]), dict(recovered.packets[0])
        self.assertNotEqual(first.pop('token'), second.pop('token'))
        self.assertEqual(first, second)

    def test_unqualified_hub_rejects_an_explicit_recovery_id_before_mutation(self):
        registry = self.registry(False)
        with patch.object(cli, 'connect', return_value=(registry, False)) as connect:
            with self.assertRaises(cli.Fail):
                cli.call('fed_code_share', {'repo': 'falcon', 'operation_id': 'unsupported'})
        connect.assert_called_once()
        self.assertEqual(registry.packets[0]['verb'], 'fed_verbs')

    def test_malformed_protocol_reply_does_not_retry_the_mutation(self):
        registry, malformed = self.registry(), Socket()
        malformed.response = b'not a JSON response\n'
        with patch.object(cli, 'connect', side_effect=[(registry, False), (malformed, False)]) as connect:
            with self.assertRaises(cli.Fail) as error:
                cli.call('fed_code_share', {'repo': 'falcon', 'operation_id': 'malformed-original'})
        self.assertIn('malformed-original', str(error.exception))
        self.assertEqual(connect.call_count, 2)
        self.assertTrue(malformed.closed)


if __name__ == '__main__':
    unittest.main()
