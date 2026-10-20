"""Existing checkout resolution and retained workspace source custody."""
import asyncio
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from hub.fed.policy import rid_for_remote
from hub.store import APP_ID, MIGRATIONS, Store
from .workspace_host import WorkspaceCheckoutHost
from .messages_host import MessageStoreHost


class WorkspaceCheckoutTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve()
        self.checkout = self.path / 'checkout'
        self.checkout.mkdir(mode=0o700)
        self.remote = 'https://example.invalid/workspace.git'
        self.git('init', '-q')
        self.git('remote', 'add', 'origin', self.remote)
        (self.checkout / 'file').write_bytes(b'original workspace bytes')
        self.database = self.path / 'hub.db'
        store = Store(str(self.database))
        store.repo_add('falcon')
        store.db.execute('INSERT INTO repo_paths VALUES (?,?,?)',
            ('falcon', str(self.checkout), 'checkout'))
        store.db.close()
        self.database.chmod(0o600)
        self.policy = self.path / 'federation.toml'
        raw = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/workspace"\n'
        self.policy.write_bytes(raw)
        self.policy.chmod(0o600)
        self.rid = rid_for_remote(self.remote)
        self.pins = {'database': {'path': str(self.database), 'applicationId': APP_ID,
            'userVersion': len(MIGRATIONS)}, 'policy': {'path': str(self.policy),
            'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()}}
        self.repository = {'localName': 'falcon', 'repositoryId': self.rid,
            'normalizedRemote': 'example.invalid/workspace'}
        self.host = WorkspaceCheckoutHost(self.pins, repository=self.repository,
            local_peer='nick', checkout_path=str(self.checkout), owner_uid=os.getuid())
        self.addAsyncCleanup(self.host.close)
        await self.host.start()

    def git(self, *args):
        subprocess.run(['/usr/bin/git', '-C', str(self.checkout), *args],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

    async def test_actual_repository_resolution_and_contained_read(self):
        await self.host.check_current()
        self.assertEqual(self.host.root.read('file', repository_id=self.rid),
            b'original workspace bytes')
        (self.checkout / 'link').symlink_to(self.policy)
        for relative in ('../federation.toml', 'link', '/etc/passwd'):
            with self.subTest(relative=relative), self.assertRaises(ContractError):
                self.host.root.read(relative, repository_id=self.rid)
        self.assertNotIn(str(self.path), repr(self.host))
        await self.host.close()
        with self.assertRaises(ContractError):
            await self.host.check_current()

    async def test_changed_git_remote_refuses_current_checkout(self):
        self.git('remote', 'set-url', 'origin', 'https://example.invalid/other.git')
        with self.assertRaisesRegex(ContractError, '^capability_workspace_unavailable$'):
            await self.host.check_current()

    async def test_current_repository_mapping_change_refuses(self):
        store = Store.open_existing(str(self.database), application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid())
        try:
            store.db.execute('DELETE FROM repo_paths WHERE repo=?', ('falcon',))
        finally:
            store.db.close()
        with self.assertRaisesRegex(ContractError, '^capability_workspace_stale$'):
            await self.host.check_current()

    async def test_replaced_checkout_cannot_read_from_retained_directory(self):
        self.checkout.rename(self.path / 'previous')
        self.checkout.mkdir(mode=0o700)
        (self.checkout / 'file').write_bytes(b'replacement')
        with self.assertRaisesRegex(ContractError, '^capability_workspace_stale$'):
            self.host.root.read('file', repository_id=self.rid)
        with self.assertRaises(ContractError):
            await self.host.check_current()

    async def test_cancelled_git_check_retains_same_original_job_until_close(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.host._directory._git._run
        async def blocked(*args):
            entered.set()
            await release.wait()
            return await original(*args)
        with patch.object(type(self.host._directory._git), '_run',
                side_effect=blocked):
            current = asyncio.create_task(self.host.check_current())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                current.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await current
                with self.assertRaisesRegex(ContractError, '^capability_cleanup_incomplete$'):
                    await self.host.close(timeout=0.01)
                self.assertTrue(self.host._jobs)
                self.assertIsNotNone(self.host.root._fd)
                release.set()
                await self.host.close(timeout=3)
                self.assertIsNone(self.host.root._fd)
                self.assertTrue(all(task.done() for task in self.host._jobs))
            finally:
                release.set()
                await self.host.close(timeout=3)

    async def test_changed_policy_refuses_without_migration(self):
        self.policy.write_bytes(self.policy.read_bytes() + b'\n# changed\n')
        with self.assertRaises(ContractError):
            self.host.root.read('file', repository_id=self.rid)

    async def test_finished_cancelled_check_releases_capacity_without_closing_host(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.host._directory._git._run
        async def blocked(*args):
            entered.set()
            await release.wait()
            return await original(*args)
        with patch.object(type(self.host._directory._git), '_run', side_effect=blocked):
            current = asyncio.create_task(self.host.check_current())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                current.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await current
                originals = tuple(self.host._jobs)
                self.assertEqual(len(originals), 1)
                release.set()
                await asyncio.wait_for(asyncio.gather(*originals), 2)
                self.assertFalse(self.host._jobs)
            finally:
                release.set()
        await self.host.check_current()
        self.assertFalse(self.host._jobs)

    async def test_actual_shared_message_source_is_borrowed_and_remains_open(self):
        await self.host.close()
        source = MessageStoreHost(self.pins, repository=self.repository,
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        borrowed = WorkspaceCheckoutHost(self.pins, repository=self.repository,
            local_peer='nick', checkout_path=str(self.checkout), owner_uid=os.getuid(), source=source)
        self.addAsyncCleanup(borrowed.close)
        await borrowed.start()
        await borrowed.check_current()
        self.assertIs(borrowed._source,source)
        self.assertEqual(borrowed.root.read('file',repository_id=self.rid),b'original workspace bytes')
        await borrowed.close()
        source.check_health()
        self.assertFalse(source._closed)
        self.assertEqual(await source.db(source._store.q1,'SELECT repo FROM repos'),{'repo':'falcon'})

