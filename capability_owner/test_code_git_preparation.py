"""Qualified Git preparation refuses changes before physical submission."""
import asyncio
import copy
from dataclasses import replace
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from agentmux_contracts import canonical_bytes
from hub.fed.code_services import Checkout, GitOperations, _CodeGitPreparation
from hub.fed.policy import rid_for_remote
from hub.store import HubError
from .code_git import public_code_remote


class CodeGitPreparationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.url = 'https://github.com/org/repo.git'
        self.rid = rid_for_remote(self.url)
        self.binding = {'codeCommands': {'resourceRef': {'id': 'code-one'}}}
        self.application_session = object()
        self.shared, self.denied = True, False
        self.session = SimpleNamespace(closing=False)
        policy = SimpleNamespace(rid_of=lambda repo: self.rid if self.shared and repo == 'repo' else None,
            trust=lambda peer: 'deny' if self.denied else 'auto',
            may_receive=lambda rid, peer: not self.denied)
        self.owner = SimpleNamespace(me='alice', session=self.session, policy=policy,
            fcfg={'code_remote': 'origin'}, _code_commands=SimpleNamespace(
                _check_git_selection=self.selection))
        self.commands = []
        self.sha = 'a' * 40
        self.destination = 'refs/agentmux/alice/main'
        self.share = {'id': 'share-one', 'repo': 'repo', 'rid': self.rid,
            'from_peer': 'bob', 'ref': 'refs/agentmux/bob/main', 'sha': self.sha,
            'note': 'Original owner note', 'fetched': None}

        async def run(git, path, *args):
            self.commands.append((path, args))
            if args[:2] == ('remote', 'get-url'):
                return self.url
            if args[0] == 'rev-parse':
                return self.sha
            return None

        self.runner = patch.object(GitOperations, '_run', run)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def selection(self, binding):
        if canonical_bytes(binding) != canonical_bytes(self.binding):
            raise HubError('code Git selection changed')
        return self.application_session

    def checkout(self):
        return Checkout('repo', self.rid, '/checked/repo', 'origin', public_code_remote(self.url))

    def effect(self, kind='push'):
        return ({'kind': 'push', 'sha': self.sha, 'destination': self.destination}
            if kind == 'push' else {'kind': 'fetch', 'share': copy.deepcopy(self.share)})

    async def prepare(self, kind='push'):
        git = GitOperations(self.owner)
        checkout = self.checkout()
        prepared = await git._prepare_effect(checkout, 'bob' if kind == 'fetch' else None)
        git._authorize_preparation(prepared, deadline=time.monotonic() + 2,
            binding=self.binding, application_session=self.application_session, effect=self.effect(kind))
        return prepared

    def physical(self):
        return [args for _, args in self.commands if args[0] in ('push', 'fetch')]

    async def push(self, prepared, *, checkout=None, sha=None, destination=None, owner=None):
        return await GitOperations(owner or self.owner, prepared).push(
            checkout or self.checkout(), sha or self.sha, destination or self.destination)

    async def test_https_and_ssh_remotes_prepare_and_submit_one_fixed_push(self):
        for url in ('https://github.com/org/repo.git', 'git@github.com:org/repo.git'):
            with self.subTest(url=url):
                self.url = url
                self.commands.clear()
                prepared = await self.prepare()
                # Submission occurs on the retained child worker, not the task
                # that performed the current owner authorization.
                self.assertIsNone(await asyncio.create_task(self.push(prepared)))
                self.assertEqual(self.physical(), [('push', '--no-verify', 'origin',
                    '+' + self.sha + ':' + self.destination)])
                self.assertEqual(sum(args[0] == 'remote' for _, args in self.commands), 1)

    async def test_fetch_keeps_exact_owner_row_and_verifies_original_sha(self):
        prepared = await self.prepare('fetch')
        got = await asyncio.create_task(GitOperations(self.owner, prepared).fetch_verified(
            self.checkout(), copy.deepcopy(self.share)))
        self.assertEqual(got, self.sha)
        self.assertEqual(self.physical(), [('fetch', '--no-tags', 'origin',
            '+' + self.share['ref'] + ':' + self.share['ref'])])
        self.assertEqual(sum(args[0] == 'remote' for _, args in self.commands), 1)

    async def test_changed_sha_or_destination_refuses_before_push(self):
        for changed in ({'sha': 'b' * 40}, {'destination': 'refs/agentmux/alice/other'}):
            with self.subTest(changed=changed):
                prepared = await self.prepare()
                with self.assertRaises(HubError):
                    await self.push(prepared, **changed)
        self.assertEqual(self.physical(), [])

    async def test_changed_fetched_row_ref_sha_or_metadata_refuses_before_fetch(self):
        for field, changed in (('ref', 'refs/agentmux/bob/other'), ('sha', 'b' * 40),
                ('note', 'Changed owner note'), ('fetched', 'changed')):
            with self.subTest(field=field):
                prepared = await self.prepare('fetch')
                row = dict(self.share, **{field: changed})
                with self.assertRaises(HubError):
                    await GitOperations(self.owner, prepared).fetch_verified(self.checkout(), row)
        self.assertEqual(self.physical(), [])

    async def test_changed_checkout_or_peer_refuses_before_physical_command(self):
        for field, changed in (('path', '/other/repo'), ('remote', 'other'),
                ('url', 'github.com/other/repo'), ('repo', 'other')):
            with self.subTest(field=field):
                prepared = await self.prepare()
                with self.assertRaises(HubError):
                    await self.push(prepared, checkout=replace(self.checkout(), **{field: changed}))
        prepared = await self.prepare('fetch')
        row = dict(self.share, from_peer='carol', ref='refs/agentmux/carol/main')
        with self.assertRaises(HubError):
            await GitOperations(self.owner, prepared).fetch_verified(self.checkout(), row)
        self.assertEqual(self.physical(), [])

    async def test_expired_authority_deadline_refuses_before_push(self):
        prepared = await self.prepare()
        with patch('hub.fed.code_services.time.monotonic', return_value=prepared.deadline):
            with self.assertRaises(HubError):
                await self.push(prepared)
        self.assertEqual(self.physical(), [])

    async def test_replaced_or_closing_federation_session_refuses(self):
        prepared = await self.prepare()
        self.owner.session = SimpleNamespace(closing=False)
        with self.assertRaises(HubError):
            await self.push(prepared)
        self.owner.session = self.session
        self.session.closing = True
        with self.assertRaises(HubError):
            await self.push(prepared)
        self.assertEqual(self.physical(), [])

    async def test_changed_application_session_or_selection_refuses(self):
        prepared = await self.prepare()
        self.application_session = object()
        with self.assertRaises(HubError):
            await self.push(prepared)
        prepared = await self.prepare()
        self.binding = {'codeCommands': {'resourceRef': {'id': 'other'}}}
        with self.assertRaises(HubError):
            await self.push(prepared)
        self.assertEqual(self.physical(), [])

    async def test_current_unshare_or_peer_denial_refuses(self):
        prepared = await self.prepare()
        self.shared = False
        with self.assertRaises(HubError):
            await self.push(prepared)
        self.shared = True
        prepared = await self.prepare('fetch')
        self.denied = True
        with self.assertRaises(HubError):
            await GitOperations(self.owner, prepared).fetch_verified(self.checkout(), self.share)
        self.assertEqual(self.physical(), [])

    async def test_preparation_is_one_use_and_wrong_owner_refuses(self):
        prepared = await self.prepare()
        other = SimpleNamespace(**vars(self.owner))
        with self.assertRaises(HubError):
            await self.push(prepared, owner=other)
        await self.push(prepared)
        with self.assertRaises(HubError):
            await self.push(prepared)
        self.assertEqual(len(self.physical()), 1)

    async def test_authorization_requires_original_task_once_and_bounded_deadline(self):
        git = GitOperations(self.owner)
        prepared = await git._prepare_effect(self.checkout())
        arguments = dict(deadline=time.monotonic() + 2, binding=self.binding,
            application_session=self.application_session, effect=self.effect())
        async def foreign():
            git._authorize_preparation(prepared, **arguments)
        with self.assertRaises(HubError):
            await asyncio.create_task(foreign())
        with self.assertRaises(HubError):
            git._authorize_preparation(prepared, **dict(arguments, deadline=time.monotonic() + 6))
        git._authorize_preparation(prepared, **arguments)
        with self.assertRaises(HubError):
            git._authorize_preparation(prepared, **arguments)
        with self.assertRaises(TypeError):
            _CodeGitPreparation()
        self.assertEqual(self.physical(), [])
