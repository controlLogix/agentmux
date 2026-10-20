"""Task host recovery custody and original service/worker ownership."""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, strict_loads
from identity.test_authority import ref, SEED
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.history import OwnerHistory
from state_owner.ledger import StreamIdentity
from state_owner.task_host import TaskHost
from state_owner.test_ledger import CREATED
from state_owner import test_task_service as support


class TaskHostTests(unittest.IsolatedAsyncioTestCase):
    new_ledger = support.TaskServiceTests.new_ledger
    reset_task = support.TaskServiceTests.reset_task
    possession = support.TaskServiceTests.possession
    request = support.TaskServiceTests.request

    def setUp(self):
        support.TaskServiceTests.setUp(self)
        temporary = tempfile.TemporaryDirectory(prefix='amx-task-host-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = StreamIdentity(CREATED, 1)
        self.history = OwnerHistory(self.root/'history.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(self.history.close)
        checkpoints = self.root/'checkpoints'
        checkpoints.mkdir(mode=0o700)
        self.checkpoint = CheckpointHost(checkpoints/'checkpoint', stream='OWNER',
            commit_ref=ref('task-checkpoint'), binding=self.binding, stream_identity=self.identity)
        roots = [self.root/name for name in ('backup', 'inventory', 'keys')]
        for root in roots:
            root.mkdir(mode=0o700)
        self.backup = BackupHost(*roots, destination_id='task-backup', binding=self.binding, stream_identity=self.identity)
        self.backup.enroll_key('backup-one')
        self.now = 1000.0
        self.connection.jetstream = lambda: self.task_js
        self.host = TaskHost.from_enrolled_host(self.connection, authority=self.service.reader,
            ingress=self.service.ingress, stream='OWNER', binding=self.binding, stream_identity=self.identity,
            retention=self.policy, history=self.history, checkpoint_host=self.checkpoint,
            backup_host=self.backup, backup_key_id='backup-one', issuer_ref=ref('issuer'), signing_seed=SEED,
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            requester_reply_prefix='_INBOX.task_caller_00000001', account_public_key='A'*56,
            monotonic=lambda: self.now, clock=lambda: self.now)
        self.addAsyncCleanup(self.host.close, timeout=None)

    async def test_start_commit_checkpoint_backup_and_close_keep_borrowed_resources(self):
        with self.assertRaisesRegex(ContractError, '^task_host_unavailable$'):
            await self.host.handle(self.request(), received_reply_subject=self.reply)
        await self.host.start()
        response = await self.host.handle(self.request(), received_reply_subject=self.reply)
        self.assertEqual(strict_loads(response)['claims']['sourceRevision'], 2)
        self.assertEqual(self.history.verified_cursor, 2)
        self.now += 901
        self.host._checkpoint_if_due()
        await self.host._checkpoint_work
        self.assertEqual((await self.checkpoint.resolve()).receipt.cursor, 2)
        self.now += 3600
        await self.host._backup.run_due()
        self.assertEqual(self.backup.latest().receipt.cursor, 2)
        await self.host.close(timeout=None)
        self.assertTrue(self.host.done.is_set() and self.host.service.done.is_set())
        self.assertTrue(self.host._timer.done())
        self.assertFalse(self.history._closed)

    async def test_backup_refreshes_lost_reply_commit_without_dispatching_offer(self):
        await self.host.start()
        self.task_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.host.handle(self.request(), received_reply_subject=self.reply)
        self.assertEqual(len(self.task_js.messages), 2)
        self.now += 3601
        await self.host._backup.run_due()
        self.assertEqual(self.history.verified_cursor, 2)
        self.assertEqual(self.backup.latest().receipt.cursor, 2)
        self.assertFalse(self.connection.sent)

    async def test_startup_wait_and_close_retain_original_subscription(self):
        self.connection.release.clear()
        starting = asyncio.create_task(self.host.start())
        await self.connection.subscribed.wait()
        allocation = self.host.service._subscribe_task
        starting.cancel()
        await asyncio.gather(starting, return_exceptions=True)
        with self.assertRaisesRegex(ContractError, '^task_host_cleanup_incomplete$'):
            await self.host.close(timeout=.01)
        self.assertIs(self.host.service._subscribe_task, allocation)
        self.assertFalse(allocation.cancelled())
        self.assertFalse(self.history._closed or self.host.done.is_set())
        self.connection.release.set()
        await self.host.close(timeout=None)
        self.assertTrue(self.host.done.is_set())

    async def test_host_fence_during_final_reply_suppresses_disclosure(self):
        await self.host.start()
        handle = self.host.owner.handle
        async def commit_then_fence(*args, **kwargs):
            stored = await handle(*args, **kwargs)
            self.host._closed = True
            return stored
        with patch.object(self.host.owner, 'handle', side_effect=commit_then_fence):
            with self.assertRaisesRegex(ContractError, '^task_host_unavailable$'):
                await self.host.handle(self.request(), received_reply_subject=self.reply)
        self.assertEqual(len(self.task_js.messages), 2)
        self.assertFalse(self.connection.sent)
