"""Original Git ownership with a real disposable Hub Store and held workers."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError
from hub.server import Hub
from hub.store import Store
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.fed.code_services import Checkout, GitOperations
from hub.fed.envelope import make
from hub.fed.policy import Policy, rid_for_remote
from .code_git import CodeGitCoordinator, public_code_remote


class CodeGitTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(self.directory.name + '/hub.db')
        self.addCleanup(self.store.db.close)
        self.hub = object.__new__(Hub)
        self.hub.store, self.hub.stop = self.store, asyncio.Event()
        self.hub.dbx = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.dbx.shutdown, wait=True)
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'one'
        self.fed.cfg = {'federation': {'peer': 'alice'}}
        self.fed.session = FederationSession()
        self.coordinator = CodeGitCoordinator(self.hub, self.fed, self.fed.session)
        self.owners = [self.coordinator]
        rid = rid_for_remote('https://example.test/repo')
        dest, sha = 'refs/agentmux/alice/topic_aaaaaaaa', 'a' * 40
        self.fields = dict(operation_id='original-one',
            principal={'authenticatedCaller': 'operator', 'caller': 'operator'},
            request_digest='b' * 64, binding={'hubId': 'one', 'scope': {'projectId': 'repo'}},
            checkout=Checkout('repo', rid, '/checked/checkout', 'origin', 'https://example.test/repo'),
            destination=dest, sha=sha,
            envelope=make('code', 'alice', 'one', rid, '*', {'ref': dest, 'sha': sha, 'note': 'original'}))
        self.authorize = AsyncMock()

    async def asyncTearDown(self):
        for owner in self.owners:
            await owner.close()

    def restart(self):
        owner = CodeGitCoordinator(self.hub, self.fed, self.fed.session)
        self.owners.append(owner)
        return owner

    async def lookup(self, owner=None, **changes):
        return await (owner or self.coordinator).lookup(authorize=self.authorize, **{**self.fields, **changes})

    def fetch_fields(self):
        fields = {k: v for k, v in self.fields.items() if k not in ('envelope', 'destination', 'sha')}
        fields['share'] = dict(id='owner-share', repo='repo', rid=self.fields['checkout'].rid,
            from_peer='alice', ref=self.fields['destination'], sha=self.fields['sha'],
            author='operator', base=None, files='one.txt', stat='', log='', note='original',
            untrusted=0, fetched=None, at='2026-10-17T00:00:00Z')
        return fields

    async def test_success_restart_returns_exact_original_without_git(self):
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            self.assertIsNone(await self.coordinator.push(authorize=self.authorize, **self.fields))
            self.assertEqual((await self.lookup())['state'], 'succeeded')
            restarted = self.restart()
            self.assertIsNone(await restarted.push(authorize=self.authorize, **self.fields))
            self.assertEqual(push.await_count, 1)
            self.assertEqual((await self.lookup(restarted))['intent']['envelope'], self.fields['envelope'])
            await restarted.confirm(**self.fields)
            self.assertIsNone(await self.lookup(restarted))

    async def test_repeated_cancellation_joins_same_git_then_persists_success(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def held(*args):
            started.set()
            await release.wait()
        with patch.object(GitOperations, 'push', AsyncMock(side_effect=held)) as push:
            caller = asyncio.create_task(self.coordinator.push(authorize=self.authorize, **self.fields))
            await started.wait()
            for _ in range(2):
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            self.assertEqual(push.await_count, 1)
            self.assertEqual((await self.lookup())['state'], 'succeeded')
            self.assertFalse(self.coordinator._workers)

    async def test_cancel_during_terminal_sql_joins_original_write(self):
        started, release = threading.Event(), threading.Event()
        original = self.coordinator._transition
        def held(intent, old, new, result=None):
            if new == 'succeeded':
                started.set()
                release.wait(5)
            return original(intent, old, new, result)
        with patch.object(self.coordinator, '_transition', side_effect=held), \
                patch.object(GitOperations, 'push', AsyncMock(return_value=None)):
            caller = asyncio.create_task(self.coordinator.push(authorize=self.authorize, **self.fields))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 5))
                caller.cancel()
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            self.assertEqual((await self.lookup())['state'], 'succeeded')

    async def test_error_is_fixed_uncertain_and_restart_never_pushes(self):
        with patch.object(GitOperations, 'push', AsyncMock(side_effect=TimeoutError('private stderr'))) as push:
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.coordinator.push(authorize=self.authorize, **self.fields)
            original = await self.lookup()
            self.assertEqual(original['state'], 'uncertain')
            self.assertNotIn('private stderr', str(original))
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.restart().push(authorize=self.authorize, **self.fields)
            with self.assertRaises(ContractError):
                await self.coordinator.confirm(**self.fields)
            self.assertEqual(push.await_count, 1)

    async def test_dispatching_restart_refuses_and_lookup_is_read_only(self):
        intent = self.coordinator._intent(**self.fields)
        await self.hub.db(self.coordinator._prepare, intent)
        await self.hub.db(self.coordinator._transition, intent, 'prepared', 'dispatching')
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            owner = self.restart()
            self.assertEqual((await self.lookup(owner))['state'], 'dispatching')
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await owner.push(authorize=self.authorize, **self.fields)
            push.assert_not_awaited()

    async def test_prepared_restart_requires_fresh_authority_and_identical_intent(self):
        await self.hub.db(self.coordinator._prepare, self.coordinator._intent(**self.fields))
        owner = self.restart()
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            await owner.push(authorize=self.authorize, **self.fields)
            self.authorize.assert_awaited_once()
            push.assert_awaited_once()

    async def test_changed_principal_request_binding_or_body_refuses(self):
        await self.hub.db(self.coordinator._prepare, self.coordinator._intent(**self.fields))
        env = copy.deepcopy(self.fields['envelope'])
        env['data']['note'] = 'replacement'
        variants = [dict(principal={'authenticatedCaller': 'other', 'caller': 'operator'}),
            dict(request_digest='c' * 64), dict(binding={'hubId': 'other'}), dict(envelope=env)]
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            for change in variants:
                with self.subTest(change=list(change)):
                    with self.assertRaisesRegex(ContractError, '^code_git_intent_conflict$'):
                        await self.coordinator.push(authorize=self.authorize, **{**self.fields, **change})
            push.assert_not_awaited()

    async def test_record_capacity_and_private_input_refusal_before_push(self):
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            for index in range(32):
                fields = {**self.fields, 'operation_id': str(index)}
                env = copy.deepcopy(fields['envelope'])
                env['id'] = 'share-' + str(index)
                fields['envelope'] = env
                await self.hub.db(self.coordinator._prepare, self.coordinator._intent(**fields))
            with self.assertRaisesRegex(ContractError, '^code_git_capacity$'):
                await self.coordinator.push(authorize=self.authorize, **self.fields)
            for binding in ({'token': 'do-not-retain'}, {'large': 'x' * 1048576}):
                with self.assertRaises(ContractError):
                    await self.coordinator.push(authorize=self.authorize, **{**self.fields, 'binding': binding})
            push.assert_not_awaited()
        self.assertEqual(self.store.q1("SELECT count(*) n FROM fed_state WHERE k LIKE 'legacy-code-git:%'")['n'], 32)

    async def test_close_fences_new_calls_and_joins_original_without_closing_store(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def held(*args):
            started.set()
            await release.wait()
        with patch.object(GitOperations, 'push', AsyncMock(side_effect=held)):
            caller = asyncio.create_task(self.coordinator.push(authorize=self.authorize, **self.fields))
            await started.wait()
            closing = asyncio.create_task(self.coordinator.close())
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            with self.assertRaisesRegex(ContractError, '^code_git_unavailable$'):
                await self.lookup()
            release.set()
            await caller
            with self.assertRaises(asyncio.CancelledError):
                await closing
            await self.coordinator.close()
            self.assertEqual(self.store.q1('SELECT count(*) n FROM fed_state')['n'], 1)
            self.assertFalse(self.fed.session.closing)

    async def test_replaced_session_after_authority_refuses_effect(self):
        async def replace():
            self.fed.session = FederationSession()
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            with self.assertRaisesRegex(ContractError, '^code_git_unavailable$'):
                await self.coordinator.push(authorize=replace, **self.fields)
            push.assert_not_awaited()
        original = await self.hub.db(self.coordinator._read, self.coordinator._intent(**self.fields))
        self.assertEqual(original['state'], 'uncertain')

    async def test_relabeling_retained_envelope_with_new_operation_refuses(self):
        await self.hub.db(self.coordinator._prepare, self.coordinator._intent(**self.fields))
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            with self.assertRaisesRegex(ContractError, '^code_git_intent_conflict$'):
                await self.coordinator.push(authorize=self.authorize,
                    **{**self.fields, 'operation_id': 'replacement'})
            push.assert_not_awaited()

    async def test_two_coordinators_cannot_dispatch_same_original_twice(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def held(*args):
            started.set()
            await release.wait()
        with patch.object(GitOperations, 'push', AsyncMock(side_effect=held)) as push:
            caller = asyncio.create_task(self.coordinator.push(authorize=self.authorize, **self.fields))
            await started.wait()
            try:
                with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                    await self.restart().push(authorize=self.authorize, **self.fields)
            finally:
                release.set()
            await caller
            self.assertEqual(push.await_count, 1)

    async def test_close_joins_operation_not_unrelated_caller_work(self):
        returned, caller_release = asyncio.Event(), asyncio.Event()
        async def caller():
            await self.coordinator.push(authorize=self.authorize, **self.fields)
            returned.set()
            await caller_release.wait()
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)):
            task = asyncio.create_task(caller())
            await returned.wait()
            try:
                await asyncio.wait_for(self.coordinator.close(), 1)
                self.assertFalse(task.done())
            finally:
                caller_release.set()
                await task

    async def test_lost_terminal_write_leaves_dispatching_and_forbids_repeat(self):
        original = self.coordinator._transition
        def lost(intent, old, new, result=None):
            if new in ('succeeded', 'uncertain'):
                raise OSError('private storage failure')
            return original(intent, old, new, result)
        with patch.object(self.coordinator, '_transition', side_effect=lost), \
                patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.coordinator.push(authorize=self.authorize, **self.fields)
            self.assertEqual((await self.lookup())['state'], 'dispatching')
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.restart().push(authorize=self.authorize, **self.fields)
            self.assertEqual(push.await_count, 1)

    async def test_denied_authority_never_dispatches_or_confirms(self):
        async def denied():
            raise ContractError('authority_refused')
        with patch.object(GitOperations, 'push', AsyncMock(return_value=None)) as push:
            with self.assertRaisesRegex(ContractError, '^authority_refused$'):
                await self.coordinator.push(authorize=denied, **self.fields)
            push.assert_not_awaited()
            self.assertEqual((await self.lookup())['state'], 'uncertain')
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.coordinator.confirm(**self.fields)

    async def test_credentialed_remote_is_not_retained_and_exact_url_change_refuses(self):
        private_url = 'https://private-user:private-password@example.test/repo.git?token=private-query#private-fragment'
        rid = rid_for_remote(private_url)
        checkout = Checkout('repo', rid, '/checked/checkout', 'origin', private_url)
        env = copy.deepcopy(self.fields['envelope'])
        env['rid'] = rid
        env['data']['remote'] = public_code_remote(private_url)
        fields = {**self.fields, 'checkout': checkout, 'envelope': env}
        self.fed.cfg['repos'] = {'repo': {'remote': private_url}}
        self.fed.policy = Policy(self.fed.cfg, {})
        # Exercise the existing remote-name lookup and repository check. Only
        # the external command boundary is controlled; no network is contacted.
        with patch.object(GitOperations, '_run', AsyncMock(side_effect=[private_url, ''])) as run:
            await self.coordinator.push(authorize=self.authorize, **fields)
            self.assertEqual(run.await_args_list[0].args, ('/checked/checkout', 'remote', 'get-url', 'origin'))
            self.assertEqual(run.await_args_list[1].args[1:4], ('push', '--no-verify', 'origin'))
        raw = self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-code-git:%'")['v']
        for private in ('private-user', 'private-password', 'private-query', 'private-fragment'):
            self.assertNotIn(private, raw)
        result = await self.coordinator.lookup(authorize=self.authorize, **fields)
        self.assertEqual(result['intent']['checkout']['url'], 'example.test/repo')
        changed = Checkout('repo', rid, '/checked/checkout', 'origin', private_url.replace('private-password', 'replacement'))
        with self.assertRaisesRegex(ContractError, '^code_git_intent_conflict$'):
            await self.coordinator.lookup(authorize=self.authorize, **{**fields, 'checkout': changed})
        env['data']['remote'] = private_url
        with self.assertRaisesRegex(ContractError, '^code_git_intent_invalid$'):
            await self.coordinator.lookup(authorize=self.authorize, **{**fields, 'envelope': env})

    async def test_actual_local_git_push_fetch_and_succeeded_restart_without_git(self):
        root = Path(self.directory.name)
        checkout_path, remote_path = root / 'checkout', root / 'remote.git'
        git_env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_TERMINAL_PROMPT': '0'}
        def git(*args):
            return subprocess.run(['/usr/bin/git', *map(str, args)], check=True, capture_output=True,
                text=True, stdin=subprocess.DEVNULL, timeout=10, env=git_env).stdout.strip()
        git('init', '--bare', remote_path)
        git('init', checkout_path)
        git('-C', checkout_path, 'config', 'user.name', 'Local fixture')
        git('-C', checkout_path, 'config', 'user.email', 'fixture@example.invalid')
        (checkout_path / 'one.txt').write_text('Original local content\n')
        git('-C', checkout_path, 'add', 'one.txt')
        git('-C', checkout_path, 'commit', '-m', 'Original local fixture')
        git('-C', checkout_path, 'remote', 'add', 'origin', remote_path)
        sha = git('-C', checkout_path, 'rev-parse', 'HEAD')
        remote = str(remote_path)
        rid, dest = rid_for_remote(remote), 'refs/agentmux/alice/local_' + sha[:8]
        self.fed.cfg['repos'] = {'repo': {'remote': remote}}
        self.fed.policy = Policy(self.fed.cfg, {})
        self.hub.io = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.io.shutdown, wait=True)
        fields = {**self.fields, 'checkout': Checkout('repo', rid, str(checkout_path), 'origin', remote),
            'sha': sha, 'destination': dest,
            'envelope': make('code', 'alice', 'one', rid, '*',
                {'sha': sha, 'ref': dest, 'remote': public_code_remote(remote)})}
        with patch.dict(os.environ, git_env):
            await self.coordinator.push(authorize=self.authorize, **fields)
        self.assertEqual(git('--git-dir', remote_path, 'rev-parse', dest), sha)
        self.assertEqual((await self.coordinator.lookup(authorize=self.authorize, **fields))['state'], 'succeeded')
        await self.coordinator.close()
        restarted = self.restart()
        with patch.object(GitOperations, '_run', AsyncMock(side_effect=AssertionError('unexpected repeat'))) as run:
            self.assertIsNone(await restarted.push(authorize=self.authorize, **fields))
            run.assert_not_awaited()
        self.assertEqual(git('--git-dir', remote_path, 'rev-parse', dest), sha)

        fetch_path = root / 'fetch-checkout'
        git('init', fetch_path)
        git('-C', fetch_path, 'remote', 'add', 'origin', remote_path)
        fetch_fields = self.fetch_fields()
        fetch_fields.update(operation_id='original-fetch',
            checkout=Checkout('repo', rid, str(fetch_path), 'origin', remote))
        fetch_fields['share'].update(id=fields['envelope']['id'], rid=rid, ref=dest, sha=sha)
        with patch.dict(os.environ, git_env):
            self.assertEqual(await restarted.fetch(authorize=self.authorize, **fetch_fields), sha)
        self.assertEqual(git('-C', fetch_path, 'rev-parse', dest), sha)
        retained = await restarted.lookup_fetch(authorize=self.authorize, **fetch_fields)
        self.assertEqual(retained['intent']['share'], fetch_fields['share'])
        self.assertEqual(retained['intent']['effectKind'], 'fetch')
        self.assertEqual(retained['result'], sha)
        with patch.object(GitOperations, '_run', AsyncMock(side_effect=AssertionError('unexpected repeat'))) as run:
            newest = self.restart()
            self.assertEqual(await newest.fetch(authorize=self.authorize, **fetch_fields), sha)
            run.assert_not_awaited()
            await newest.confirm_fetch(**fetch_fields)
            self.assertIsNone(await newest.lookup_fetch(authorize=self.authorize, **fetch_fields))

    async def test_fetch_repeated_cancel_retains_exact_original_sha_and_row(self):
        fields = self.fetch_fields()
        started, release = asyncio.Event(), asyncio.Event()
        async def held(checkout, share):
            started.set()
            await release.wait()
            return share['sha']
        with patch.object(GitOperations, 'fetch_verified', AsyncMock(side_effect=held)) as fetch:
            task = asyncio.create_task(self.coordinator.fetch(authorize=self.authorize, **fields))
            await started.wait()
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            result = await self.coordinator.lookup_fetch(authorize=self.authorize, **fields)
            self.assertEqual(result['result'], fields['share']['sha'])
            self.assertEqual(result['intent']['share'], fields['share'])
            self.assertEqual(await self.restart().fetch(authorize=self.authorize, **fields), fields['share']['sha'])
            self.assertEqual(fetch.await_count, 1)

    async def test_uncertain_fetch_and_dispatching_restart_never_repeat(self):
        fields = self.fetch_fields()
        with patch.object(GitOperations, 'fetch_verified', AsyncMock(side_effect=TimeoutError('private'))) as fetch:
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.coordinator.fetch(authorize=self.authorize, **fields)
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.restart().fetch(authorize=self.authorize, **fields)
            self.assertEqual(fetch.await_count, 1)
            with self.assertRaises(ContractError):
                await self.coordinator.confirm_fetch(**fields)
        fields = copy.deepcopy(fields)
        fields['operation_id'], fields['share']['id'] = 'lost-fetch', 'lost-share'
        intent = self.coordinator._intent(effect_kind='fetch', **fields)
        await self.hub.db(self.coordinator._prepare, intent)
        await self.hub.db(self.coordinator._transition, intent, 'prepared', 'dispatching')
        with patch.object(GitOperations, 'fetch_verified', AsyncMock()) as fetch:
            with self.assertRaisesRegex(ContractError, '^code_git_uncertain$'):
                await self.restart().fetch(authorize=self.authorize, **fields)
            fetch.assert_not_awaited()

    async def test_fetch_bad_source_cross_kind_and_changed_original_refuse(self):
        fields = self.fetch_fields()
        with patch.object(GitOperations, 'fetch_verified', AsyncMock()) as fetch:
            for change in ({'rid': 'other'}, {'repo': 'other'}, {'from_peer': 'other'},
                           {'ref': 'refs/heads/main'}, {'sha': 'A' * 40}, {'id': ''}):
                with self.subTest(change=change):
                    bad = {**fields, 'share': {**fields['share'], **change}}
                    with self.assertRaisesRegex(ContractError, '^code_git_intent_invalid$'):
                        await self.coordinator.fetch(authorize=self.authorize, **bad)
            fetch.assert_not_awaited()
        intent = self.coordinator._intent(effect_kind='fetch', **fields)
        await self.hub.db(self.coordinator._prepare, intent)
        with self.assertRaisesRegex(ContractError, '^code_git_intent_conflict$'):
            await self.coordinator.push(authorize=self.authorize, **self.fields)
        with self.assertRaisesRegex(ContractError, '^code_git_intent_conflict$'):
            await self.coordinator.lookup_fetch(authorize=self.authorize,
                **{**fields, 'share': {**fields['share'], 'note': 'changed original'}})
