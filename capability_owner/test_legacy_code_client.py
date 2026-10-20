"""Actual Hub code callers and signed owners; session transport and Git are controlled."""
import asyncio
import copy
from contextvars import ContextVar
from datetime import timedelta
import hashlib
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from agentmux_contracts import canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.fed import ledger
from hub.fed.code_bridge import CodeBridgeIntents
from hub.fed.code_services import Checkout, GitOperations, RepositoryDirectory
from hub.fed.message_bridge import MessageBridgeIntents
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.code import Code
from hub.fed.plugins.messages import Messages
from hub.fed.runtime import Federation
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, SEED, ref
from identity.test_service import _Clock
from identity.test_knowledge_client import material
from .legacy_code_client import LegacyCodeCommandClient
from .legacy_messages_client import LegacyMessageCommandClient
from .message_bridge_service import MessageBridgeService
from . import test_code_bridge_owner as support
from . import test_message_bridge_owner as message_support


class LegacyCodeTests(support.CodeBridgeFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        if self._testMethodName == 'test_signed_owner_expiry_stops_prepared_physical_submission':
            for grant in self.record['state']['grants']:
                if grant['ref'] in (self.code_grants['human']['federation-code-publish'],
                                   self.code_grants['human']['federation-code-outcome']):
                    grant['expiresAt'] = (NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
            self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_messages_client', 'capability_owner.legacy_code_client',
                       'capability_owner.message_bridge_service', 'hub.fed.message_bridge', 'hub.fed.code_bridge'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.hub = object.__new__(Hub)
        self.hub.store, self.hub.db = self.store, self.owner.db
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('code-client-proof', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.store.repo_add('falcon', aliases=('github.com/adag/falcon',))
        self.fed.presence, self.fed.session = {}, self.owner.session
        self.fed.connected, self.fed.last_error = False, None
        self.addAsyncCleanup(self.fed.session.close)
        self.fed.stats = dict.fromkeys(('received', 'duplicates', 'dropped', 'quarantined', 'delivered', 'errors'), 0)
        self.fed.log = Mock()
        self.fed.loop = self.fed.wake = None
        self.fed.nc = SimpleNamespace(_subs={}, publish=AsyncMock())
        self.fed._qualified_code = self.fed._qualified_messages = True
        self.hub.fed = self.fed
        self.message_resource = self.open_resource()
        self.message_endpoint = MessageBridgeService(self.service.ingress, resources=(self.message_resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.message_endpoint.close, timeout=None)
        self.submitted, self.drop_contract = [], None
        self.sessions = tuple(self.session_for(self.code_key(identity), 'code', self.endpoint)
            for identity in ('human', 'service'))
        key = message_support.MessageBridgeServiceTests.application_key(self)
        self.message_sessions = (self.session_for(key, 'message', self.message_endpoint),)
        self.client = LegacyCodeCommandClient(self.hub, self.sessions).bind(self.fed)
        self.message_client = LegacyMessageCommandClient(self.hub, self.message_sessions).bind(self.fed)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.addAsyncCleanup(self.message_client.close, timeout=None)
        self.fed._code_commands, self.fed._message_commands = self.client, self.message_client
        self.hub._code_commands = self.client
        self.fed._code_intents = CodeBridgeIntents(self.fed, self.client)
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.message_client)
        adapters = [TrustedPluginAdapter(plugin, builtin_context_factory(plugin.name)) for plugin in (Code(), Messages())]
        self.fed.plugin_adapters = {p.name: p for p in adapters}
        self.fed.plugins = {p.name: p.original for p in adapters}
        self.fed.routes = {kind: p for p in adapters for kind in p.original.handles}
        self.fed.verbs, self.fed.plugin_verbs = self.fed._core_verbs(), {}
        for adapter in adapters:
            for name, verb in adapter.verbs().items():
                key = 'fed_' + adapter.name + '_' + name
                self.fed.verbs[key], self.fed.plugin_verbs[key] = verb, (adapter, name)
        checkout = Checkout('falcon', self.resource.repository_id, '/controlled/checkout', 'origin',
            'git@github.com:Adag/Falcon.git')
        self.remote_lookup_hook = None
        async def readonly_git(path, *args):
            if path != checkout.path or args != ('remote', 'get-url', checkout.remote):
                raise AssertionError('Only the remote lookup is controlled at this command boundary')
            if self.remote_lookup_hook is not None:
                await self.remote_lookup_hook()
            return checkout.url
        self.git_lookup = AsyncMock(side_effect=readonly_git)
        timer = patch.object(GitOperations, '_run', self.git_lookup)
        timer.start()
        self.addCleanup(timer.stop)
        self.git = {}
        self.original_git_push = GitOperations.push
        for name, value in (('revision', 'a' * 40), ('branch', 'feature'), ('push', None),
                ('fetch_verified', 'a' * 40), ('summary', (None, ['one.py'], 'one.py | 1 +', 'log'))):
            mock = AsyncMock(return_value=value)
            timer = patch.object(GitOperations, name, mock)
            timer.start()
            self.addCleanup(timer.stop)
            self.git[name] = mock
        timer = patch.object(RepositoryDirectory, 'checkout', AsyncMock(return_value=checkout))
        timer.start()
        self.addCleanup(timer.stop)

    def code_key(self, identity):
        selected = material()
        route = selected.pop('knowledgeCommands')
        selected.update(scope=self.scope, callerRef=ref(identity))
        route.update(authenticatedCaller='operator' if identity == 'human' else 'federation',
            resourceRef=ref('task-one'), transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            repository={'localName': 'falcon', 'repositoryId': self.resource.repository_id},
            grantRefs=self.code_grants[identity])
        selected['codeCommands'] = route
        return ApplicationClientKey(selected)

    def session_for(self, key, family, endpoint):
        loop = asyncio.get_running_loop()
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        selected = key.selection[family + 'Commands']
        setattr(session, '_' + family + '_enrollment', canonical_bytes({
            **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
            family + 'Commands': selected}))
        def submit(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False):
            if include_valid_until and (family, contract_id) not in (
                    ('code', 'federation-code-outcome'), ('code', 'federation-code-read'),
                    ('message', 'federation-message-outcome')):
                raise AssertionError('Validity metadata is only requested for original outcome admission')
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': selected['transportRef'], 'grantRef': selected['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.code_client_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=selected['subject'], now=NOW)
            response = asyncio.run_coroutine_threadsafe(endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_contract == contract_id:
                self.drop_contract = None
                raise TimeoutError()
            options = {'include_valid_until': True} if include_valid_until else {}
            return key.verify_command_response(response, raw, subject=selected['subject'], now=NOW, **options)
        setattr(session, family + '_command', submit)
        return session

    async def request_hub(self, verb, args):
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps({
            'token': 'operator-secret', 'verb': verb, 'args': args}).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=True)
        self.assertFalse(self.hub._authenticated_callers)
        return json.loads(writer.write.call_args.args[0])

    async def test_actual_share_fetch_list_panel_keep_owner_values(self):
        response = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Review original'})
        self.assertTrue(response['ok'], response)
        original = response['result']
        row = self.store.q1('SELECT * FROM p_code_shares WHERE id=?', (original['id'],))
        self.assertEqual((row['sha'], row['note'], row['author']), ('a' * 40, 'Review original', 'operator'))
        listing = await self.request_hub('fed_code_list', {'repo': 'falcon'})
        self.assertTrue(listing['ok'], listing)
        self.assertEqual(listing['result'][0]['id'], original['id'])
        fetched = await self.request_hub('fed_code_fetch', {'id': original['id']})
        self.assertTrue(fetched['ok'], fetched)
        self.assertTrue(fetched['result']['verified'])
        self.assertIsNotNone(self.store.q1('SELECT fetched FROM p_code_shares')['fetched'])
        panel_errors = []
        original_read = self.client.read
        async def observed_read(*args):
            try:
                return await original_read(*args)
            except Exception as error:
                panel_errors.append((type(error).__name__, str(error)))
                raise
        with patch.object(self.client, 'read', side_effect=observed_read):
            panel = await self.request_hub('fed_panel', {})
        self.assertTrue(panel['ok'], panel)
        self.assertEqual(panel_errors, [])
        code = next(value for value in panel['result']['panels'] if value['plugin'] == 'code')
        self.assertEqual(code['rows'][0][-1], 'yes')
        self.git['push'].assert_awaited_once()
        self.git['fetch_verified'].assert_awaited_once()
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-code-%'"), [])

    async def test_lost_publish_reply_recovers_original_without_second_git_effect(self):
        args = {'repo': 'falcon', 'note': 'Original uncertain reply'}
        self.drop_contract = 'federation-code-publish'
        self.assertFalse((await self.request_hub('fed_code_share', args))['ok'])
        original = self.store.q1('SELECT id FROM p_code_shares')['id']
        response = await self.request_hub('fed_code_share', args)
        self.assertTrue(response['ok'], response)
        self.assertEqual(response['result']['id'], original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.git['push'].assert_awaited_once()

    def retained_code_group(self):
        return self.store.q("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-code-%' "
            "OR k LIKE 'legacy-message-client:%' ORDER BY k")

    def published_code_group(self):
        items = [strict_loads(row['payload']) for row in self.store.q('SELECT payload FROM fed_outbox')]
        code = [item for item in items if item['type'] == 'code']
        handoffs = [item for item in items if item['type'] == 'handoff']
        self.assertEqual(len(code), 1)
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0]['data']['code'], code[0]['id'])
        self.git['push'].assert_awaited_once()
        return code[0], handoffs[0]

    async def test_confirmed_handoff_survives_failed_group_completion(self):
        args = {'repo': 'falcon', 'note': 'Retain confirmed handoff', 'to': 'peer:alice/falcon/worker'}
        with patch.object(self.client, '_finish_effect', AsyncMock(side_effect=RuntimeError('controlled completion failure'))):
            first = await self.request_hub('fed_code_share', args)
        self.assertFalse(first['ok'], first)
        original_code, original_handoff = self.published_code_group()
        self.assertEqual(len(self.retained_code_group()), 4)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-code-completion:pending:%'")), 1)
        retried = await self.request_hub('fed_code_share', args)
        self.assertTrue(retried['ok'], retried)
        self.assertEqual(retried['result']['id'], original_code['id'])
        self.assertEqual(retried['result']['handoff']['id'], original_handoff['id'])
        self.assertEqual(self.published_code_group(), (original_code, original_handoff))
        self.assertEqual(self.retained_code_group(), [])

    async def test_lost_handoff_reply_survives_client_replacement(self):
        args = {'repo': 'falcon', 'note': 'Recover original handoff', 'to': 'peer:alice/falcon/worker'}
        self.drop_contract = 'federation-message-send'
        first = await self.request_hub('fed_code_share', args)
        self.assertFalse(first['ok'], first)
        original_code, original_handoff = self.published_code_group()
        self.assertEqual(len(self.retained_code_group()), 4)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-code-completion:pending:%'")), 1)
        original_send = next(item for item in self.submitted if item['contractId'] == 'federation-message-send')
        await self.client.close(timeout=None)
        await self.message_client.close(timeout=None)
        self.client = LegacyCodeCommandClient(self.hub, self.sessions).bind(self.fed)
        self.message_client = LegacyMessageCommandClient(self.hub, self.message_sessions).bind(self.fed)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.addAsyncCleanup(self.message_client.close, timeout=None)
        self.fed._code_commands, self.fed._message_commands = self.client, self.message_client
        self.fed._code_intents = CodeBridgeIntents(self.fed, self.client)
        self.hub._code_commands = self.client
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.message_client)
        retried = await self.request_hub('fed_code_share', args)
        self.assertTrue(retried['ok'], retried)
        self.assertEqual(retried['result']['id'], original_code['id'])
        self.assertEqual(retried['result']['handoff']['id'], original_handoff['id'])
        self.assertEqual(self.published_code_group(), (original_code, original_handoff))
        sends = [item for item in self.submitted if item['contractId'] == 'federation-message-send']
        self.assertEqual(sends, [original_send])
        queries = [item['payload']['input'] for item in self.submitted
            if item['contractId'] == 'federation-message-outcome']
        self.assertTrue(any(item['operationId'] == original_send['operationId'] for item in queries))
        self.assertEqual(self.retained_code_group(), [])

    async def test_group_completion_sql_failure_rolls_back_all_originals(self):
        args = {'repo': 'falcon', 'note': 'Atomic original group', 'to': 'peer:alice/falcon/worker'}
        before, deleted = [], []
        finish, forget = self.client._finish_effect, self.client._forget
        async def observed_finish(*args, **kwargs):
            before.extend(await self.hub.db(self.retained_code_group))
            return await finish(*args, **kwargs)
        def failed_forget(key, original):
            forget(key, original)
            deleted.extend(self.retained_code_group())
            raise RuntimeError('controlled final SQL failure')
        with patch.object(self.client, '_finish_effect', side_effect=observed_finish), \
                patch.object(self.client, '_forget', side_effect=failed_forget):
            first = await self.request_hub('fed_code_share', args)
        self.assertFalse(first['ok'], first)
        self.assertEqual(len(before), 4)
        self.assertEqual(len(deleted), 1)
        self.assertTrue(deleted[0]['k'].startswith('legacy-code-completion:completed:'))
        self.assertEqual(strict_loads(deleted[0]['v'])['state'], 'completed')
        self.assertEqual(self.retained_code_group(), before)
        original_code, original_handoff = self.published_code_group()
        retried = await self.request_hub('fed_code_share', args)
        self.assertTrue(retried['ok'], retried)
        self.assertEqual(retried['result']['handoff']['id'], original_handoff['id'])
        self.assertEqual(self.published_code_group(), (original_code, original_handoff))
        self.assertEqual(self.retained_code_group(), [])

    async def test_slow_git_uses_one_refresh_and_distinct_storage_handoff_proofs(self):
        async def slow(*args):
            await asyncio.sleep(5.05)
        self.git['push'].side_effect = slow
        with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as authenticate:
            result = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Review',
                'to': 'peer:alice/falcon/worker'})
        self.assertTrue(result['ok'], result)
        self.assertEqual(authenticate.await_count, 2)
        self.assertIn('handoff', result['result'])
        handoff = strict_loads(self.store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?',
            (result['result']['handoff']['id'],))['payload'])
        self.assertEqual(handoff['data']['code'], result['result']['id'])

    async def test_failed_owner_read_never_returns_local_code_row(self):
        result = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Local row exists'})
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')), 1)
        await self.endpoint.close(timeout=None)
        listing = await self.request_hub('fed_code_list', {'repo': 'falcon'})
        self.assertFalse(listing['ok'], listing)

    async def test_repeated_cancel_and_close_join_original_git_before_cleanup(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def held(*args):
            entered.set()
            await release.wait()
        self.git['push'].side_effect = held
        caller = asyncio.create_task(self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Held original'}))
        await asyncio.wait_for(entered.wait(), 2)
        closing = None
        try:
            for _ in range(2):
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
            closing = asyncio.create_task(self.client.close(timeout=None))
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            self.assertFalse(self.fed.session.closing)
        finally:
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            if closing is not None:
                await closing
        self.git['push'].assert_awaited_once()
        self.assertFalse(self.client._code_git._workers)
        self.assertFalse(self.hub._authenticated_callers)
        retained = self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-code-git:%'")
        self.assertEqual(strict_loads(retained['v'])['state'], 'succeeded')
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])

    async def test_revoked_publish_owner_grant_refuses_before_physical_git(self):
        target = self.code_grants['human']['federation-code-publish']
        self.claims.update(operationId='revoke-code-target', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': target})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        result = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'No current owner grant'})
        self.assertFalse(result['ok'], result)
        self.git['push'].assert_not_awaited()
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])

    async def test_revoked_fetched_owner_grant_refuses_before_physical_git(self):
        published = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Original share'})
        self.assertTrue(published['ok'], published)
        target = self.code_grants['human']['federation-code-fetched']
        self.claims.update(operationId='revoke-code-target', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': target})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        result = await self.request_hub('fed_code_fetch', {'id': published['result']['id']})
        self.assertFalse(result['ok'], result)
        self.git['fetch_verified'].assert_not_awaited()
        self.assertIsNone(self.store.q1('SELECT fetched FROM p_code_shares')['fetched'])

    async def revoke_during_lookup(self, command):
        # The preparation must stay on the actual original Hub caller task.
        self.assertIs(self.hub._current_code_share_invocation().task, asyncio.current_task())
        target = self.code_grants['human']['federation-code-' + command]
        self.claims.update(operationId='revoke-during-lookup', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': target})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')

    async def test_publish_grant_revoked_during_remote_lookup_refuses_before_push(self):
        async def revoke():
            await self.revoke_during_lookup('publish')
        self.remote_lookup_hook = revoke
        response = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Revoke during lookup'})
        self.assertFalse(response['ok'], response)
        self.git_lookup.assert_awaited_once()
        self.git['push'].assert_not_awaited()
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_fetched_grant_revoked_during_remote_lookup_refuses_before_fetch(self):
        published = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Original share'})
        self.assertTrue(published['ok'], published)
        self.git_lookup.reset_mock()
        async def revoke():
            await self.revoke_during_lookup('fetched')
        self.remote_lookup_hook = revoke
        response = await self.request_hub('fed_code_fetch', {'id': published['result']['id']})
        self.assertFalse(response['ok'], response)
        self.git_lookup.assert_awaited_once()
        self.git['fetch_verified'].assert_not_awaited()
        self.assertIsNone(self.store.q1('SELECT fetched FROM p_code_shares')['fetched'])

    async def test_retained_success_after_lost_reply_still_requires_current_publish_grant(self):
        arguments = {'repo': 'falcon', 'note': 'Retained original'}
        self.drop_contract = 'federation-code-publish'
        self.assertFalse((await self.request_hub('fed_code_share', arguments))['ok'])
        original = self.store.q1('SELECT id FROM p_code_shares')['id']
        target = self.code_grants['human']['federation-code-publish']
        self.claims.update(operationId='revoke-retained-publish', contractId='identity-revoke', grantRef=ref('grant'),
            expectedVersion=2, payload={'authorityId': 'authority-one', 'targetRef': target})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        response = await self.request_hub('fed_code_share', arguments)
        self.assertFalse(response['ok'], response)
        self.git['push'].assert_awaited_once()
        self.assertEqual(self.store.q1('SELECT id FROM p_code_shares')['id'], original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-code-git:%'")), 1)

    async def test_signed_owner_expiry_stops_prepared_physical_submission(self):
        deadlines, physical, after_delay = [], [], []
        original_authorize = self.client._authorize_git
        async def observe_authorize(admitted, *args):
            deadline = await original_authorize(admitted, *args)
            deadlines.append((deadline, admitted.expires_monotonic))
            return deadline
        original_check = GitOperations._check_effect
        async def delayed_check(git, checkout, peer=None, *, effect=None):
            if git._preparation is not None:
                deadline, local_expiry = deadlines[-1]
                self.assertLess(deadline, local_expiry)
                await asyncio.sleep(max(0, deadline - time.monotonic()) + 0.02)
                after_delay.append(time.monotonic())
            return await original_check(git, checkout, peer, effect=effect)
        async def commands(path, *args):
            if args == ('remote', 'get-url', 'origin'):
                return 'git@github.com:Adag/Falcon.git'
            if args[:2] == ('push', '--no-verify'):
                physical.append(args)
                return ''
            raise AssertionError('Unexpected Git command')
        with patch.object(self.client, '_authorize_git', side_effect=observe_authorize), \
                patch.object(GitOperations, 'push', self.original_git_push), \
                patch.object(GitOperations, '_check_effect', delayed_check), \
                patch.object(GitOperations, '_run', side_effect=commands):
            response = await self.request_hub('fed_code_share', {'repo': 'falcon', 'note': 'Short owner admission'})
        self.assertFalse(response['ok'], response)
        self.assertEqual(len(deadlines), 1)
        self.assertLess(deadlines[0][0], deadlines[0][1])
        self.assertEqual(len(after_delay), 1)
        self.assertGreaterEqual(after_delay[0], deadlines[0][0])
        self.assertLess(after_delay[0], deadlines[0][1])
        self.assertEqual(physical, [])
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    def broker_message(self, item):
        from nats.aio.msg import Msg
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = subscription
        self.fed.session.own_subscription(subscription)
        return Msg(_client=self.fed.nc, subject='am.code.alice.' + item['rid'], data=canonical_bytes(item),
            _sid=1, reply='$JS.ACK.AM_SHARE.consumer.1.1.1.1.0')

    async def test_actual_runtime_inbound_and_duplicate_confirm_durable_seen(self):
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        item['data']['ref'] = 'refs/agentmux/alice/feature_aaaaaaaa'
        message = self.broker_message(item)
        result = await self.fed.receive(message.subject, message.data, message)
        self.assertEqual(result, 'delivered')
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(self.store.q1('SELECT id FROM p_code_shares')['id'], item['id'])
        self.assertEqual(await self.fed.receive(message.subject, message.data, message), 'duplicate')
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-code-index']), 1)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-code-client:%'"), [])

    async def test_actual_held_approval_requires_original_hub_proof_and_durable_decision(self):
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        item['data']['ref'] = 'refs/agentmux/alice/feature_aaaaaaaa'
        subject = 'am.code.alice.' + item['rid']
        qid = ledger.quarantine_add(self.store, item, subject, 'code', 'alice', 'approve')
        response = await self.request_hub('fed_approve', {'id': qid})
        self.assertTrue(response['ok'], response)
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(self.store.q1('SELECT untrusted FROM p_code_shares')['untrusted'], 1)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-code-client:%'"), [])
