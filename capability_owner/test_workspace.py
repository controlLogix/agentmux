"""Real local filesystem containment and owned-worker cancellation controls."""
import asyncio
from pathlib import Path
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from hub.fed.code_services import Checkout
from .workspace import WorkspaceRoot
from . import test_receiver


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        (self.path/'src').mkdir()
        (self.path/'src'/'file').write_bytes(b'original')
        self.root = WorkspaceRoot(Checkout('repo','repo-id',str(self.path),'origin','private-url'))
        self.addCleanup(self.root.close)

    def test_reads_and_refuses_paths_links_special_files(self):
        self.assertEqual(self.root.read('src/file',repository_id='repo-id'), b'original')
        (self.path/'link').symlink_to(self.path/'src',target_is_directory=True)
        (self.path/'src'/'file-link').symlink_to(self.path/'src'/'file')
        os.mkfifo(self.path/'pipe')
        for relative in ('../file','/etc/passwd','src/../src/file','src//file','link/file',
                         'src/file-link','pipe','src','src\\file','src/file\n'):
            with self.subTest(relative=relative), self.assertRaises(ContractError):
                self.root.read(relative,repository_id='repo-id')
        with self.assertRaises(ContractError):
            self.root.read('src/file',repository_id='other')
        self.assertNotIn(str(self.path),repr(self.root))
        self.root.close()
        with self.assertRaisesRegex(ContractError,'^capability_workspace_stale$'):
            self.root.read('src/file',repository_id='repo-id')

    def test_large_file_refused(self):
        (self.path/'large').write_bytes(b'x'*45001)
        with self.assertRaises(ContractError):
            self.root.read('large',repository_id='repo-id')


class WorkspaceWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await test_receiver.ReceiverTests.asyncSetUp(self)

    async def test_cancel_keeps_original_worker_until_joined(self):
        started, release = threading.Event(), threading.Event()
        def blocked(*args, **kwargs):
            started.set()
            if not release.wait(3):
                raise RuntimeError('test did not release worker')
            return b'private'
        with tempfile.TemporaryDirectory() as path:
            root=WorkspaceRoot(Checkout('repo','repo-id',path,'origin','private-url'))
            try:
                with patch.object(root,'read',side_effect=blocked):
                    request=asyncio.create_task(self.receiver._workspace_read(root,'file','repo-id'))
                    self.assertTrue(await asyncio.to_thread(started.wait,1))
                    request.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await request
                    with self.assertRaisesRegex(ContractError,'^capability_cleanup_incomplete$'):
                        await self.receiver.close(timeout=0.01)
                    self.assertEqual(len(self.receiver._workers),1)
                    release.set()
                    await self.receiver.close(timeout=2)
                    self.assertFalse(self.receiver._workers)
            finally:
                release.set()
                await self.receiver.close(timeout=3)
                root.close()
