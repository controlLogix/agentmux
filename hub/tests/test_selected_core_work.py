"""Selected endpoint consumer checks through actual Hub authentication and Work owners."""
import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from capability_owner.test_work_rpc import WorkRpcTests
from hub.core_endpoint import SelectedCoreRequest, selected_core_request


class SelectedCoreWorkTests(WorkRpcTests):
    async def test_selected_worker_messages_require_current_signed_read_permission(self):
        from agentmux_contracts import canonical_bytes, strict_loads
        await self.agent()
        self.install_client()
        self.hub._legacy_identity = None
        self.hub.bridge = None
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        message = self.store.post('virtual:operator', 'agent:' + self.caller, 'note', 'Read and acknowledge')
        for verb, args in (('post', {'to': 'virtual:operator', 'body': 'Worker reply'}),
                ('inbox', {}), ('ack', {'ids': [message['id']]})):
            result = await self.selected_packet('falcon', verb, args, operation_id=None, token='agent-secret')
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['caller'], self.caller)
        state = strict_loads(self.js.messages[-1].data)
        next(g for g in state['state']['grants']
            if g['ref'] == self.work_grants['human']['federation-work-read'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        for verb, args in (('post', {'to': 'virtual:operator', 'body': 'Must refuse'}),
                ('inbox', {'ack': True}), ('ack', {'ids': [message['id']]})):
            before = (self.store.q('SELECT * FROM messages'), self.store.q('SELECT * FROM deliveries'))
            result = await self.selected_packet('falcon', verb, args, operation_id=None, token='agent-secret')
            self.assertFalse(result['ok'], result)
            self.assertEqual((self.store.q('SELECT * FROM messages'),
                self.store.q('SELECT * FROM deliveries')), before)

    async def test_selected_message_expiry_before_commit_has_no_effect(self):
        sender = await self.message_agent()
        message = self.store.post('agent:' + sender, 'virtual:operator', 'note', 'Selected')
        original = self.hub._selected_message_guard
        async def expire_before_commit(*args, **kwargs):
            result = await original(*args, **kwargs)
            guard = result[0] if kwargs.get('classify') else result
            def expired():
                later = time.monotonic() + 10
                with patch('hub.server.time.monotonic', return_value=later):
                    guard()
            return (expired, result[1]) if kwargs.get('classify') else expired
        for verb, args in (
                ('ack', {'ids': [message['id']]}),
                ('inbox', {'ack': True}),
                ('post', {'to': sender, 'body': 'Must not be written'})):
            with self.subTest(verb=verb):
                before = (self.store.q('SELECT * FROM messages'), self.store.q('SELECT * FROM deliveries'))
                with patch.object(self.hub, '_selected_message_guard', side_effect=expire_before_commit):
                    result = await self.selected_packet('falcon', verb, args, operation_id=None)
                self.assertFalse(result['ok'], result)
                self.assertIn('expired', result['error'])
                self.assertEqual((self.store.q('SELECT * FROM messages'),
                    self.store.q('SELECT * FROM deliveries')), before)

    async def test_selected_signed_addresses_preserve_alias_and_current_registration(self):
        from agentmux_contracts import ContractError
        from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
        from hub.tests.test_legacy_identity_client import binding, session_with
        from identity.legacy_identity import VerifiedLegacyAliasResolution
        sender = await self.message_agent()
        self.store.db.execute('INSERT INTO legacy_names VALUES (?,?)', ('adopted-name', sender))
        self.store.repo_add('falcon', groups=['selected'])
        self.store.team_add('falcon', 'selected', [sender], 'worker')
        requested, revoked = [], False
        def query(_session, registrations=None, **kwargs):
            if revoked:
                raise ContractError('legacy_identity_unavailable')
            requested.extend(registrations)
            return VerifiedLegacyAliasResolution(tuple(binding(row['canonicalSession'],
                row['registrationGeneration'], alias=row['legacyAlias']) for row in registrations),
                datetime.now(timezone.utc) + timedelta(seconds=20))
        self.hub._legacy_identity = EnrolledLegacyIdentityResolver({'falcon': session_with(query)},
            local_source_hub_id='hub-one')
        self.store.configure_identity_fencing('hub-one', require_signed_expiry=True)
        for address in ('adopted-name', 'agent:falcon/worker/one', 'agent:' + sender,
                'role:group:selected/worker', 'role:team:falcon/selected/worker',
                'team:falcon/selected', 'role:*/worker'):
            result = await self.selected_packet('falcon', 'post', {'to': address, 'body': 'Selected'}, operation_id=None)
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['result']['recipients'], [sender])
        self.assertTrue(any(row['legacyAlias'] == 'adopted-name' for row in requested))
        before = self.store.q('SELECT * FROM messages')
        revoked = True
        result = await self.selected_packet('falcon', 'post', {'to': 'adopted-name', 'body': 'Refuse'}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM messages'), before)
        revoked = False
        original = self.hub._selected_message_guard
        async def replace_before_commit(*args, **kwargs):
            guard = await original(*args, **kwargs)
            self.store.set_state(sender, 'dead')
            self.store.register('falcon', 'worker', 'one', 'codex', {}, legacy='adopted-name')
            self.store.set_state(sender, 'ready')
            return guard
        with patch.object(self.hub, '_selected_message_guard', side_effect=replace_before_commit):
            result = await self.selected_packet('falcon', 'post', {'to': 'adopted-name', 'body': 'Refuse'}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM messages'), before)

    async def test_selected_typed_work_message_uses_owner_and_preserves_opaque_ref(self):
        await self.message_agent()
        await self.open_both_repositories(); self.install_client()
        selected = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Selected')
        foreign = self.store.work_create('operator', 'other', 'role:other/worker', 'Foreign')
        result = await self.selected_packet('falcon', 'post', {'to': 'virtual:operator',
            'body': 'Selected result', 'work_id': selected['id'], 'ref': foreign['id']}, operation_id=None)
        self.assertTrue(result['ok'], result)
        before = self.store.q('SELECT * FROM messages')
        result = await self.selected_packet('falcon', 'post', {'to': 'virtual:operator',
            'body': 'Foreign result', 'work_id': foreign['id'], 'ref': selected['id']}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM messages'), before)

    async def message_agent(self, repository='falcon', agent='one'):
        self.hub._legacy_identity = None
        self.hub.bridge = None
        session = self.store.register(repository, 'worker', agent, 'codex',
            {'capabilities': [], 'max_active': 1})
        self.store.set_state(session, 'ready')
        return session

    async def test_selected_ack_keeps_complete_batch_order_and_noops(self):
        sender = await self.message_agent()
        rows = [self.store.post('agent:' + sender, 'virtual:operator', 'note', str(index))
            for index in range(25)]
        self.store.ack('virtual:operator', [rows[0]['id']])
        self.store.db.execute("UPDATE deliveries SET state='dead' WHERE message_id=?", (rows[1]['id'],))
        unrelated = self.store.post('virtual:operator', 'agent:' + sender, 'note', 'Not this recipient')
        ids = [rows[24]['id'], rows[0]['id'], rows[1]['id'], rows[0]['id'], 'unknown', unrelated['id']]
        result = await self.selected_packet('falcon', 'ack', {'ids': ids}, operation_id=None)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['result']['acked'], ids[:4])
        empty = await self.selected_packet('falcon', 'ack', {'ids': []}, operation_id=None)
        self.assertEqual(empty['result'], {'acked': []})

    async def test_selected_ack_refuses_mixed_batch_before_any_mutation(self):
        sender = await self.message_agent()
        other = await self.message_agent('other')
        selected = self.store.post('agent:' + sender, 'virtual:operator', 'note', 'Selected', ref='other-opaque')
        foreign = self.store.post('agent:' + other, 'virtual:operator', 'note', 'Foreign', ref='falcon')
        before = self.store.q('SELECT * FROM deliveries ORDER BY message_id')
        result = await self.selected_packet('falcon', 'ack', {'ids': [selected['id'], foreign['id']]}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM deliveries ORDER BY message_id'), before)
        result = await self.selected_packet('falcon', 'ack', {'ids': [selected['id']]}, operation_id=None)
        self.assertTrue(result['ok'], result)

    async def test_selected_ack_refuses_ambiguous_virtual_message(self):
        self.hub._legacy_identity = None
        message = self.store.post('virtual:hub', 'virtual:operator', 'note', 'Global', ref='falcon')
        result = await self.selected_packet('falcon', 'ack', {'ids': [message['id']]}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q1('SELECT state FROM deliveries WHERE message_id=?',
            (message['id'],))['state'], 'queued')

    async def test_selected_post_resolves_addresses_and_rejects_mixed_broadcasts(self):
        sender = await self.message_agent()
        for address in ('agent:falcon/worker/one', 'agent:' + sender, sender, 'role:falcon/worker'):
            result = await self.selected_packet('falcon', 'post', {'to': address, 'body': address}, operation_id=None)
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['result']['recipients'], [sender])
        await self.message_agent('other')
        before = self.store.q('SELECT * FROM messages')
        result = await self.selected_packet('falcon', 'post', {'to': 'role:*/worker', 'body': 'Mixed'}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM messages'), before)

    async def test_selected_post_duplicate_cannot_disclose_foreign_original(self):
        selected = await self.message_agent()
        other = await self.message_agent('other')
        self.store.post('virtual:operator', 'agent:' + other, 'note', 'Original', idem_key='original')
        before = self.store.q('SELECT * FROM messages')
        result = await self.selected_packet('falcon', 'post',
            {'to': selected, 'body': 'Retry', 'idem_key': 'original'}, operation_id=None)
        self.assertFalse(result['ok'], result)
        self.assertEqual(self.store.q('SELECT * FROM messages'), before)

    async def test_selected_operator_peek_never_marks_or_acknowledges(self):
        sender = await self.message_agent()
        message = self.store.post('agent:' + sender, 'virtual:orchestrator', 'note', 'Selected')
        before = self.store.q('SELECT * FROM deliveries')
        result = await self.selected_packet('falcon', 'inbox',
            {'session': 'virtual:orchestrator', 'ack': True}, operation_id=None)
        self.assertTrue(result['ok'], result)
        self.assertEqual([row['id'] for row in result['result']['messages']], [message['id']])
        self.assertEqual(result['result']['acked'], [])
        self.assertEqual(self.store.q('SELECT * FROM deliveries'), before)

    async def test_selected_inbox_filters_before_limit_and_keeps_foreign_untouched(self):
        sender = await self.message_agent()
        other = await self.message_agent('other')
        for index in range(25):
            self.store.post('agent:' + other, 'virtual:operator', 'note', str(index))
        selected = self.store.post('agent:' + sender, 'virtual:operator', 'note', 'Selected')
        foreign = self.store.q('SELECT * FROM deliveries WHERE message_id<>?', (selected['id'],))
        result = await self.selected_packet('falcon', 'inbox', {'limit': 1}, operation_id=None)
        self.assertTrue(result['ok'], result)
        self.assertEqual([row['id'] for row in result['result']['messages']], [selected['id']])
        self.assertEqual(self.store.q('SELECT * FROM deliveries WHERE message_id<>?', (selected['id'],)), foreign)

    async def test_selected_status_and_events_preserve_scoped_original_records(self):
        sender = await self.message_agent()
        other = await self.message_agent('other')
        await self.open_both_repositories(); self.install_client()
        selected_work = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Selected')
        self.store.work_create('operator', 'other', 'role:other/worker', 'Foreign')
        selected = self.store.post('agent:' + sender, 'virtual:operator', 'note', 'Selected')
        foreign = self.store.post('agent:' + other, 'virtual:operator', 'note', 'Foreign')
        self.store.db.execute("UPDATE deliveries SET state='dead' WHERE message_id=?", (selected['id'],))
        self.store.set_state(sender, 'dead')
        self.store.team_add('falcon', 'selected', [sender], 'worker')
        self.store.team_add('other', 'foreign', [other], 'worker')
        status = await self.selected_packet('falcon', 'status', {}, operation_id=None)
        self.assertTrue(status['ok'], status)
        self.assertEqual(status['result']['repos'], ['falcon'])
        self.assertEqual([row['session'] for row in status['result']['agents']], [sender])
        self.assertEqual(status['result']['deliveries'], {'dead': 1})
        self.assertEqual(status['result']['work'], {'ready': 1})
        self.assertEqual([row['message_id'] for row in status['result']['dead']], [selected['id']])
        self.assertEqual([row['team'] for row in status['result']['teams']], ['selected'])
        selected_events = [row for row in self.store.events(limit=-1) if
            row['entity_id'] in (sender, selected_work['id'], selected['id'] + '>virtual:operator')]
        events = await self.selected_packet('falcon', 'events', {'limit': -1}, operation_id=None)
        self.assertTrue(events['ok'], events)
        self.assertEqual(events['result'], selected_events)
        for _ in range(30):
            self.store.event('agent', other, 'foreign')
        tail = await self.selected_packet('falcon', 'events', {'limit': 1, 'tail': True}, operation_id=None)
        self.assertEqual(tail['result'], selected_events[-1:])
        forward = await self.selected_packet('falcon', 'events', {'limit': 1}, operation_id=None)
        self.assertEqual(forward['result'], selected_events[:1])
        filtered = await self.selected_packet('falcon', 'events', {'limit': 1, 'entity': 'work'}, operation_id=None)
        self.assertEqual(filtered['result'][0]['entity_id'], selected_work['id'])
        empty = await self.selected_packet('falcon', 'events', {'limit': 0, 'tail': True}, operation_id=None)
        self.assertEqual(empty['result'], [])
        self.assertEqual(self.store.q1('SELECT state FROM deliveries WHERE message_id=?',
            (foreign['id'],))['state'], 'queued')

    async def selected_packet(self, repository, verb, args, *, operation_id='selected-original',
                              token='operator-secret'):
        if not hasattr(self.hub, '_selected_endpoint'):
            self.hub._selected_endpoint = SimpleNamespace(check=Mock(),
                route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon', '/other': 'other'}}))
        request = {'verb': verb, 'args': args, 'token': token}
        if operation_id is not None:
            request['operationId'] = operation_id
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()), at_eof=lambda: False)
        replies = []
        writer = SimpleNamespace(write=lambda raw: replies.append(json.loads(raw)),
            drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        async def invoke():
            context = selected_core_request.set(SelectedCoreRequest(self.hub._selected_endpoint,
                repository, '/' + repository, asyncio.current_task()))
            try:
                await self.hub.handle_conn(reader, writer, tcp=True)
            finally:
                selected_core_request.reset(context)
        await asyncio.create_task(invoke())
        self.assertEqual(len(replies), 1)
        return replies[0]

    async def test_selected_dispatch_recovery_and_reads_are_confined(self):
        await self.open_both_repositories(); self.install_client()
        created = await self.selected_packet('other', 'work_add', {**self.args, 'to': 'role:other/worker'})
        self.assertTrue(created['ok'], created)
        original = self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'")
        refused = await self.selected_packet('falcon', 'work_add', {**self.args, 'to': 'role:other/worker'})
        self.assertFalse(refused['ok'], refused)
        self.assertEqual(self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:%'"), original)
        listed = await self.selected_packet('falcon', 'work_list', {}, operation_id=None)
        self.assertTrue(listed['ok'], listed)
        self.assertEqual(listed['result'], [])
        shown = await self.selected_packet('falcon', 'work_show', {'work_id': created['result']['id']}, operation_id=None)
        self.assertTrue(shown['ok'], shown)
        self.assertIsNone(shown['result'])
        recovered = await self.selected_packet('other', 'work_add', {**self.args, 'to': 'role:other/worker'})
        self.assertEqual(recovered['result'], created['result'])
        self.assertEqual(len(self.mutations()), 1)

    async def test_selected_dispatch_keeps_cross_home_claim_eligibility(self):
        self.store.repo_add('falcon', groups=['shared']); self.store.repo_add('other', groups=['shared'])
        await self.agent(home='other', maximum=3)
        await self.open_both_repositories(); self.install_client()
        self.store.db.execute('UPDATE agents SET token_sha=? WHERE session=?',
            (hashlib.sha256(b'agent-secret').hexdigest(), self.caller))
        wanted = self.store.work_create('operator', 'falcon', 'role:group:shared/worker', 'Selected', priority=20)
        foreign = self.store.work_create('operator', 'other', 'role:group:shared/worker', 'Foreign', priority=1)
        claimed = await self.selected_packet('falcon', 'claim', {}, token='agent-secret')
        self.assertTrue(claimed['ok'], claimed)
        self.assertEqual(claimed['result']['claimed']['id'], wanted['id'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        heartbeat = await self.selected_packet('falcon', 'heartbeat', {}, token='agent-secret', operation_id='heartbeat')
        self.assertTrue(heartbeat['ok'], heartbeat)
        self.assertEqual(heartbeat['result'], {'renewed': 1})

    async def test_concurrent_selected_requests_do_not_share_repository(self):
        await self.open_both_repositories(); self.install_client()
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'One')
        self.store.work_create('operator', 'other', 'role:other/worker', 'Two')
        one, two = await asyncio.gather(
            self.selected_packet('falcon', 'work_list', {}, operation_id=None),
            self.selected_packet('other', 'work_list', {}, operation_id=None))
        self.assertTrue(one['ok'], one); self.assertTrue(two['ok'], two)
        self.assertEqual({row['repo'] for row in one['result']}, {'falcon'})
        self.assertEqual({row['repo'] for row in two['result']}, {'other'})
        self.assertIsNone(selected_core_request.get())
