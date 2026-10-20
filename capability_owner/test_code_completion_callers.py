"""Actual Hub replies retain completed code results across caller loss."""
import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from agentmux_contracts import canonical_bytes, strict_loads
from hub.fed.code_bridge import CodeBridgeIntents
from hub.fed.message_bridge import MessageBridgeIntents
from identity.test_authority import ref
from .legacy_code_client import LegacyCodeCommandClient
from .legacy_messages_client import LegacyMessageCommandClient
from .test_legacy_code_client import LegacyCodeTests


class CodeCompletionCallerTests(LegacyCodeTests):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.hub._code_commands = self.client

    async def request_packet(self, arguments, *, operation_id=None, fail=None, token='operator-secret',
                             verb='fed_code_share'):
        packet = {'token': token, 'verb': verb, 'args': arguments}
        if operation_id is not None:
            packet['operationId'] = operation_id
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(packet).encode()),
            at_eof=lambda: False)
        responses = []
        def write(raw):
            responses.append(json.loads(raw))
            if fail == 'write':
                raise BrokenPipeError('controlled completed reply loss')
        writer = SimpleNamespace(write=Mock(side_effect=write),
            drain=AsyncMock(side_effect=BrokenPipeError('controlled drain loss') if fail == 'drain' else None),
            close=Mock(), is_closing=lambda: False)
        if fail:
            with self.assertRaises(BrokenPipeError):
                await self.hub.handle_conn(reader, writer, tcp=True)
        else:
            await self.hub.handle_conn(reader, writer, tcp=True)
        self.assertTrue(responses, 'Hub did not reach its final reply')
        return responses[0]

    def completed_records(self):
        return [strict_loads(row['v']) for row in self.store.q(
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-code-completion:completed:%'")]

    def code_events(self):
        return [strict_loads(row['payload']) for row in self.store.q('SELECT payload FROM fed_outbox')
            if strict_loads(row['payload'])['type'] == 'code']

    async def test_explicit_write_and_drain_loss_replay_exact_original_without_git(self):
        for failure in ('write', 'drain'):
            with self.subTest(failure=failure):
                arguments = {'repo': 'falcon', 'note': 'Original ' + failure}
                before = self.git['push'].await_count
                lost = await self.request_packet(arguments, operation_id='lost-' + failure, fail=failure)
                self.assertTrue(lost['ok'], lost)
                replay = await self.request_packet(arguments, operation_id='lost-' + failure)
                self.assertTrue(replay['ok'], replay)
                self.assertEqual(replay['result'], lost['result'])
                self.assertEqual(self.git['push'].await_count, before + 1)
                replay_again = await self.request_packet(arguments, operation_id='lost-' + failure)
                self.assertEqual(replay_again['result'], lost['result'])
                self.assertEqual(self.git['push'].await_count, before + 1)
        self.assertEqual(len(self.code_events()), 2)
        self.assertEqual(len(self.completed_records()), 2)

    async def test_explicit_completed_handoff_replays_after_client_replacement(self):
        arguments = {'repo': 'falcon', 'note': 'Original handoff result',
            'to': 'peer:alice/falcon/worker'}
        lost = await self.request_packet(arguments, operation_id='restart-handoff', fail='drain')
        self.assertTrue(lost['ok'], lost)
        for client in (self.client, self.message_client):
            await client.close(timeout=None)
        self.client = LegacyCodeCommandClient(self.hub, self.sessions).bind(self.fed)
        self.message_client = LegacyMessageCommandClient(self.hub, self.message_sessions).bind(self.fed)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.addAsyncCleanup(self.message_client.close, timeout=None)
        self.fed._code_commands, self.fed._message_commands = self.client, self.message_client
        self.hub._code_commands = self.client
        self.fed._code_intents = CodeBridgeIntents(self.fed, self.client)
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.message_client)
        replay = await self.request_packet(arguments, operation_id='restart-handoff')
        self.assertTrue(replay['ok'], replay)
        self.assertEqual(replay['result'], lost['result'])
        events = [strict_loads(row['payload']) for row in self.store.q('SELECT payload FROM fed_outbox')]
        self.assertEqual(sorted(item['type'] for item in events), ['code', 'handoff'])
        self.git['push'].assert_awaited_once()

    async def test_same_id_refuses_changed_arguments_or_invalid_current_local_identity(self):
        arguments = {'repo': 'falcon', 'note': 'Original identity and input'}
        original = await self.request_packet(arguments, operation_id='bound-input')
        self.assertTrue(original['ok'], original)
        changed = await self.request_packet({**arguments, 'note': 'Substituted input'}, operation_id='bound-input')
        self.assertFalse(changed['ok'], changed)
        invalid = await self.request_packet(arguments, operation_id='bound-input', token='wrong-current-token')
        self.assertFalse(invalid['ok'], invalid)
        self.git['push'].assert_awaited_once()
        self.assertEqual(len(self.code_events()), 1)

    async def test_same_id_refuses_changed_selected_source(self):
        arguments = {'repo': 'falcon', 'note': 'Original selected source'}
        original = await self.request_packet(arguments, operation_id='bound-source')
        self.assertTrue(original['ok'], original)
        session = self.sessions[0]
        enrollment = strict_loads(session._code_enrollment)
        enrollment['codeCommands']['resourceRef'] = ref('substituted-code-owner')
        session._code_enrollment = canonical_bytes(enrollment)
        changed = await self.request_packet(arguments, operation_id='bound-source')
        self.assertFalse(changed['ok'], changed)
        self.git['push'].assert_awaited_once()
        self.assertEqual(len(self.code_events()), 1)

    async def test_completed_replay_requires_current_original_publish_grant(self):
        arguments = {'repo': 'falcon', 'note': 'Current original owner grant'}
        original = await self.request_packet(arguments, operation_id='current-grant')
        self.assertTrue(original['ok'], original)
        self.claims.update(operationId='revoke-completed-original', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2, payload={'authorityId': 'authority-one',
                'targetRef': self.code_grants['human']['federation-code-publish']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        refused = await self.request_packet(arguments, operation_id='current-grant')
        self.assertFalse(refused['ok'], refused)
        self.git['push'].assert_awaited_once()
        self.assertEqual(len(self.code_events()), 1)

    async def test_completed_handoff_replay_requires_current_original_message_grant(self):
        arguments = {'repo': 'falcon', 'note': 'Current message owner grant',
            'to': 'peer:alice/falcon/worker'}
        original = await self.request_packet(arguments, operation_id='current-message-grant')
        self.assertTrue(original['ok'], original)
        self.claims.update(operationId='revoke-completed-message', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2, payload={'authorityId': 'authority-one',
                'targetRef': self.legacy_grants['human']['federation-message-send']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        refused = await self.request_packet(arguments, operation_id='current-message-grant')
        self.assertFalse(refused['ok'], refused)
        self.git['push'].assert_awaited_once()

    async def test_current_rotated_local_credential_does_not_change_original_intent(self):
        import hashlib
        arguments = {'repo': 'falcon', 'note': 'Same principal after credential rotation'}
        original = await self.request_packet(arguments, operation_id='rotated-credential')
        self.assertTrue(original['ok'], original)
        self.hub.operator_sha = hashlib.sha256(b'new-operator-secret').hexdigest()
        replay = await self.request_packet(arguments, operation_id='rotated-credential', token='new-operator-secret')
        self.assertTrue(replay['ok'], replay)
        self.assertEqual(replay['result'], original['result'])
        self.git['push'].assert_awaited_once()

    async def test_unknown_original_git_effect_never_becomes_a_new_dispatch(self):
        arguments = {'repo': 'falcon', 'note': 'Unknown original physical result'}
        self.git['push'].side_effect = RuntimeError('controlled unknown Git result')
        first = await self.request_packet(arguments, operation_id='unknown-original')
        self.assertFalse(first['ok'], first)
        self.git['push'].side_effect = None
        retry = await self.request_packet(arguments, operation_id='unknown-original')
        self.assertFalse(retry['ok'], retry)
        self.git['push'].assert_awaited_once()
        self.assertEqual(self.code_events(), [])

    async def test_completed_fetch_replays_exact_result_without_another_fetch(self):
        share = await self.request_packet({'repo': 'falcon', 'note': 'Fetch source'}, operation_id='fetch-source')
        self.assertTrue(share['ok'], share)
        arguments = {'id': share['result']['id']}
        lost = await self.request_packet(arguments, operation_id='original-fetch', fail='drain', verb='fed_code_fetch')
        self.assertTrue(lost['ok'], lost)
        replay = await self.request_packet(arguments, operation_id='original-fetch', verb='fed_code_fetch')
        self.assertTrue(replay['ok'], replay)
        self.assertEqual(replay['result'], lost['result'])
        self.git['fetch_verified'].assert_awaited_once()
        self.git['push'].assert_awaited_once()

    async def test_new_operation_id_resolves_a_deliberate_new_head(self):
        arguments = {'repo': 'falcon', 'note': 'Share current HEAD'}
        first = await self.request_packet(arguments, operation_id='head-first')
        self.assertTrue(first['ok'], first)
        self.git['revision'].return_value = 'b' * 40
        same = await self.request_packet(arguments, operation_id='head-first')
        self.assertEqual(same['result'], first['result'])
        new = await self.request_packet(arguments, operation_id='head-second')
        self.assertTrue(new['ok'], new)
        self.assertEqual(new['result']['sha'], 'b' * 40)
        self.assertNotEqual(new['result']['id'], first['result']['id'])
        self.assertEqual(self.git['push'].await_count, 2)
        self.assertEqual(len(self.code_events()), 2)

    async def test_legacy_detected_reply_loss_replays_then_allows_a_new_normal_call(self):
        arguments = {'repo': 'falcon', 'note': 'Legacy reply recovery'}
        lost = await self.request_packet(arguments, fail='write')
        self.assertTrue(lost['ok'], lost)
        self.assertEqual(len(self.completed_records()), 1)
        replay = await self.request_packet(arguments)
        self.assertTrue(replay['ok'], replay)
        self.assertEqual(replay['result'], lost['result'])
        self.git['push'].assert_awaited_once()
        self.assertEqual(self.completed_records(), [])
        new = await self.request_packet(arguments)
        self.assertTrue(new['ok'], new)
        self.assertNotEqual(new['result']['id'], lost['result']['id'])
        self.assertEqual(self.git['push'].await_count, 2)

    async def test_concurrent_same_operation_id_joins_one_original_code_effect(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def held(*args, **kwargs):
            entered.set()
            await release.wait()
        self.git['push'].side_effect = held
        arguments = {'repo': 'falcon', 'note': 'Concurrent original operation'}
        first = asyncio.create_task(self.request_packet(arguments, operation_id='concurrent-original'))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 10)
            second = asyncio.create_task(self.request_packet(arguments, operation_id='concurrent-original'))
            await asyncio.sleep(.02)
            self.assertFalse(second.done())
            release.set()
            results = await asyncio.gather(first, second)
            self.assertTrue(all(result['ok'] for result in results), results)
            self.assertEqual(results[0]['result'], results[1]['result'])
            self.git['push'].assert_awaited_once()
            self.assertEqual(len(self.code_events()), 1)
        finally:
            release.set()
            await asyncio.gather(*(task for task in (first, second) if task is not None), return_exceptions=True)


def load_tests(loader, standard_tests, pattern):
    # The inherited fixture also contains its original tests. Keep this suite
    # limited to the new outer-response and operation-identity cases.
    names = [name for name in CodeCompletionCallerTests.__dict__ if name.startswith('test_')]
    return unittest.TestSuite(CodeCompletionCallerTests(name) for name in sorted(names))
