"""Completed code results survive outer Hub response loss over native owners."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.fed.code_bridge import CodeBridgeIntents
from hub.fed.code_services import GitOperations
from identity.test_authority import ref
from .legacy_code_client import LegacyCodeCommandClient
from .test_legacy_code_live import LegacyCodeLiveFixture


class CodeCompletionLiveTests(LegacyCodeLiveFixture, unittest.IsolatedAsyncioTestCase):
    async def completion_request(self, arguments, operation_id, *, failure=None):
        self.refresh_observation()
        reader = SimpleNamespace(readline=AsyncMock(return_value=canonical_bytes({
            'token': self.operator_token, 'verb': 'fed_code_share', 'args': arguments,
            'operationId': operation_id})), at_eof=lambda: False)
        responses = []
        def write(raw):
            responses.append(json.loads(raw))
            if failure == 'write':
                raise BrokenPipeError('controlled outer Hub write loss')
        writer = SimpleNamespace(write=Mock(side_effect=write),
            drain=AsyncMock(side_effect=BrokenPipeError('controlled outer Hub drain loss')
                if failure == 'drain' else None), close=Mock(), is_closing=lambda: False)
        if failure is not None:
            with self.assertRaises(BrokenPipeError):
                await self.actual_hub.handle_conn(reader, writer, tcp=True)
        else:
            await self.actual_hub.handle_conn(reader, writer, tcp=True)
        writer.close.assert_called_once()
        self.assertEqual(len(responses), 1)
        return responses[0]

    async def test_native_completed_result_replays_after_outer_loss_and_client_replacement(self):
        session = await self.native_session()
        hub = await self.make_hub((session,))
        checkout, sha = await self.git_checkout()
        pushes = []
        original_run = GitOperations._run
        async def counted(owner, path, *arguments):
            if arguments and arguments[0] == 'push':
                pushes.append(tuple(arguments))
            return await original_run(owner, path, *arguments)
        originals = []
        closed_clients = []
        with patch.object(GitOperations, '_run', counted):
            for failure in ('write', 'drain'):
                with self.subTest(failure=failure):
                    operation = 'native-outer-' + failure
                    arguments = {'repo': 'falcon', 'path': str(checkout),
                        'note': 'Native outer response ' + failure}
                    before = len(pushes)
                    lost = await self.completion_request(arguments, operation, failure=failure)
                    self.assertTrue(lost['ok'], lost)
                    share = lost['result']
                    self.assertEqual(share['sha'], sha)
                    self.assertEqual(len(pushes), before + 1)
                    self.assertEqual(await self.git('--git-dir', self.git_remote, 'rev-parse', share['ref']), sha)
                    replay = await self.completion_request(arguments, operation)
                    self.assertTrue(replay['ok'], replay)
                    self.assertEqual(replay['result'], share)

                    previous = hub._code_commands
                    await previous.close(timeout=None)
                    closed_clients.append(previous)
                    replacement = LegacyCodeCommandClient(hub, (session,)).bind(hub.fed)
                    hub._code_commands = hub.fed._code_commands = replacement
                    hub.fed._code_intents = CodeBridgeIntents(hub.fed, replacement)
                    restarted = await self.completion_request(arguments, operation)
                    self.assertTrue(restarted['ok'], restarted)
                    self.assertEqual(restarted['result'], share)
                    self.assertEqual(len(pushes), before + 1)
                    originals.append((arguments, operation, share))

            rows = self.store.q('SELECT * FROM p_code_shares')
            self.assertEqual({row['id'] for row in rows}, {item[2]['id'] for item in originals})
            self.assertTrue(all(row['sha'] == sha and row['files'] == 'original.txt' for row in rows))
            events = [strict_loads(row['payload']) for row in self.store.q('SELECT payload FROM fed_outbox')]
            self.assertEqual({event['id'] for event in events}, {item[2]['id'] for item in originals})
            self.assertEqual(len(events), 2)
            records = await hub.db(hub.store.q,
                "SELECT v FROM fed_state WHERE k LIKE 'legacy-code-completion:completed:%'")
            completed = [strict_loads(row['v']) for row in records]
            self.assertEqual({record['operationId'] for record in completed}, {item[1] for item in originals})
            self.assertNotIn(self.operator_token, canonical_bytes(completed).decode())
            for arguments, operation, share in originals:
                record = next(item for item in completed if item['operationId'] == operation)
                self.assertEqual(record['result'], share)
                self.assertEqual(record['codeSource']['result'], {'id': share['id']})
                self.assertEqual(record['codeSource']['binding']['codeCommands']['resourceRef']['id'], 'task-one')
                self.assertIsNone(record['messageSource'])

            management = await self.connect('host')
            with patch.object(self, 'host', management):
                await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
                    'targetRef': self.code_grants['federation-code-publish']})
            for arguments, operation, _ in originals:
                refused = await self.completion_request(arguments, operation)
                self.assertFalse(refused['ok'], refused)
            self.assertEqual(len(pushes), 2)
            self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)

        self.assertEqual(self.raw_code_access, [])
        await hub._code_commands.close(timeout=None)
        for client in (*closed_clients, hub._code_commands):
            self.assertFalse(client._workers)
            self.assertFalse(client._active)
        await self.join_native_clients()
        self.success = True
