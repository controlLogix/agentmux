"""Work mutations negotiate IDs and preserve one request across transport loss."""
import json
import unittest
from unittest.mock import patch

from hub import cli
from .test_code_operation_cli import Socket


class WorkOperationCliTests(unittest.TestCase):
    def setUp(self):
        timer = patch.object(cli, 'validate_callback', return_value=False)
        timer.start()
        self.addCleanup(timer.stop)

    def registry(self, qualified=True):
        return Socket({'ok': True, 'result': {'workOperationIds': qualified}})

    def test_qualified_negotiation_and_retry_keep_one_exact_work_intent(self):
        discovery, lost, recovered = self.registry(), Socket(error=ConnectionResetError()), Socket()
        with patch.object(cli, 'connect', side_effect=[(item, False) for item in (discovery, lost, recovered)]), \
                patch.object(cli.secrets, 'token_hex', return_value='a' * 48) as generate:
            self.assertTrue(cli.call('work_add', {'to': 'role:falcon/worker', 'title': 'Original'})['ok'])
        self.assertEqual(discovery.packets[0]['verb'], 'ping')
        self.assertEqual(lost.packets, recovered.packets)
        self.assertEqual(recovered.packets[0]['operationId'], 'work_' + 'a' * 48)
        generate.assert_called_once_with(24)
        self.assertTrue(all(item.closed for item in (discovery, lost, recovered)))

    def test_identical_new_calls_get_distinct_ids(self):
        sockets = [self.registry(), Socket(), self.registry(), Socket()]
        with patch.object(cli, 'connect', side_effect=[(item, False) for item in sockets]), \
                patch.object(cli.secrets, 'token_hex', side_effect=['a' * 48, 'b' * 48]):
            cli.call('heartbeat')
            cli.call('heartbeat')
        self.assertNotEqual(sockets[1].packets[0]['operationId'], sockets[3].packets[0]['operationId'])

    def test_explicit_id_is_top_level_and_original_arguments_stay_unchanged(self):
        discovery, response = self.registry(), Socket()
        args = {'work_id': 'original-work', 'operation_id': 'original-rpc'}
        with patch.object(cli, 'connect', side_effect=[(discovery, False), (response, False)]), \
                patch.object(cli.secrets, 'token_hex') as generate:
            cli.call('claim', args)
        self.assertEqual(response.packets[0]['operationId'], 'original-rpc')
        self.assertEqual(response.packets[0]['args'], {'work_id': 'original-work'})
        self.assertEqual(args['operation_id'], 'original-rpc')
        generate.assert_not_called()

    def test_unqualified_hub_keeps_no_id_one_shot_and_refuses_explicit_id(self):
        discovery, response = self.registry(False), Socket(error=EOFError())
        with patch.object(cli, 'connect', side_effect=[(discovery, False), (response, False)]) as connect:
            with self.assertRaises(cli.Fail):
                cli.call('heartbeat')
        self.assertEqual(connect.call_count, 2)
        self.assertNotIn('operationId', response.packets[0])
        with patch.object(cli, 'connect', return_value=(self.registry(False), False)) as connect:
            with self.assertRaises(cli.Fail):
                cli.call('heartbeat', {'operation_id': 'unsupported'})
        connect.assert_called_once()

    def test_federated_offer_uses_registered_operation_id_support(self):
        discovery = Socket({'ok': True, 'result': [{'verb': 'fed_work_add', 'operationIds': True}]})
        response = Socket()
        with patch.object(cli, 'connect', side_effect=[(discovery, False), (response, False)]):
            cli.call('fed_work_add', {'to': 'role:falcon/worker', 'title': 'Original', 'operation_id': 'offer-one'})
        self.assertEqual(discovery.packets[0]['verb'], 'fed_verbs')
        self.assertEqual(response.packets[0]['operationId'], 'offer-one')

    def test_refusal_or_malformed_response_does_not_retry_and_reports_original_id(self):
        for reply in (Socket({'ok': False, 'error': 'Current permission refused'}), Socket()):
            if reply.error is None and json.loads(reply.response)['ok']:
                reply.response = b'invalid-json\n'
            with patch.object(cli, 'connect', side_effect=[(self.registry(), False), (reply, False)]) as connect:
                with self.assertRaises(cli.Fail) as error:
                    cli.call('release', {'work_id': 'one', 'outcome': 'done', 'operation_id': 'retain-original'})
            self.assertIn('retain-original', str(error.exception))
            self.assertEqual(connect.call_count, 2)
            self.assertTrue(reply.closed)

    def test_main_parses_operation_id_before_positional_work_arguments(self):
        cases = [(['claim', '--operation-id', 'rpc-one', 'work-one'], 'claim'),
            (['done', '--operation-id', 'rpc-one', 'work-one'], 'release'),
            (['heartbeat', '--operation-id', 'rpc-one'], 'heartbeat'),
            (['work', 'add', '--operation-id', 'rpc-one', '--to', 'role:falcon/worker', '--title', 'Original'], 'work_add'),
            (['work', 'cancel', '--operation-id', 'rpc-one', 'work-one'], 'work_cancel')]
        result = {'id': 'work-one', 'target': 'role:falcon/worker', 'state': 'done', 'cancelled': [], 'claimed': None}
        for argv, verb in cases:
            with self.subTest(argv=argv), patch.object(cli, 'call', return_value={'ok': True, 'result': result}) as call, \
                    patch('builtins.print'):
                cli.main(argv)
            self.assertEqual(call.call_args.args[0], verb)
            self.assertEqual(call.call_args.args[1]['operation_id'], 'rpc-one')


class LifecycleOperationCliTests(unittest.TestCase):
    def test_lost_reply_retains_one_lifecycle_intent(self):
        for verb in ('spawn', 'adopt', 'kill'):
            discovery = Socket({'ok': True, 'result': {'lifecycleOperationIds': True}})
            lost, recovered = Socket(error=ConnectionResetError()), Socket()
            with self.subTest(verb=verb), patch.object(cli, 'validate_callback', return_value=False), \
                    patch.object(cli, 'connect', side_effect=[(i, False) for i in (discovery,lost,recovered)]):
                self.assertTrue(cli.call(verb, {'operation_id':'original-lifecycle','session':'falcon-worker-one'})['ok'])
                self.assertEqual(lost.packets,recovered.packets)
                self.assertEqual(recovered.packets[0]['operationId'],'original-lifecycle')
                self.assertTrue(all(i.closed for i in (discovery,lost,recovered)))

    def test_main_lifecycle_operation_options(self):
        result = {'session':'falcon-worker-one','handle':'%0','cwd':'/approved',
            'legacy':'old','cli':'codex'}
        for args in (['spawn','falcon','worker','one'],['adopt','old','falcon','worker','one'],
                ['kill','falcon-worker-one']):
            with self.subTest(args=args), patch.object(cli,'validate_callback',return_value=False), \
                    patch.object(cli,'call',return_value={'ok':True,'result':result}) as call, patch('builtins.print'):
                cli.main([*args,'--operation-id','original-lifecycle'])
                self.assertEqual(call.call_args.args[1]['operation_id'],'original-lifecycle')
