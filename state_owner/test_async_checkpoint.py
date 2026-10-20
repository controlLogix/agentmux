"""Real SQLite thread ownership and joined checkpoint-worker cancellation."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes
from state_owner import checkpoints
from state_owner.checkpoints import export_checkpoint_async, load_checkpoint
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity
from state_owner.test_ledger import BINDING, record


class AsyncCheckpointTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.identity = StreamIdentity(datetime(2026, 10, 16, tzinfo=timezone.utc), 0)
        self.history = OwnerHistory(self.root / 'source.db', BINDING, stream_identity=self.identity)
        self.addCleanup(self.history.close)
        for position in range(1, 66):
            self.history.verify_source(StoredRecord(canonical_bytes(record(
                'source-' + str(position), position, position - 1)), position))

    async def test_source_reads_stay_on_owner_thread_and_generations_restore(self):
        owner_thread = threading.get_ident()
        reads, writers = [], []
        source_at, publish = self.history._at, checkpoints._publish
        def read(*args):
            reads.append(threading.get_ident())
            return source_at(*args)
        def write(*args):
            writers.append(threading.get_ident())
            return publish(*args)
        with patch.object(self.history, '_at', side_effect=read), patch.object(checkpoints, '_publish', side_effect=write):
            first = await export_checkpoint_async(self.root / 'first.json', self.history,
                                                  BINDING, self.identity, through=33)
            second = await export_checkpoint_async(self.root / 'second.json', self.history,
                                                   BINDING, self.identity, through=65)
        self.assertTrue(reads)
        self.assertTrue(all(thread == owner_thread for thread in reads))
        self.assertTrue(writers)
        self.assertTrue(all(thread != owner_thread for thread in writers))
        for name, digest, cursor in [('first', first, 33), ('second', second, 65)]:
            restored = load_checkpoint(self.root / (name + '.json'), expected_digest=digest,
                binding=BINDING, stream_identity=self.identity, history_path=self.root / (name + '.db'))
            self.addCleanup(restored.history.close)
            self.assertEqual(restored.cursor, cursor)

    async def test_cancel_waits_for_original_writer_while_loop_remains_responsive(self):
        entered = asyncio.Event()
        release, exited = threading.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        publish = checkpoints._publish
        def blocked(*args):
            loop.call_soon_threadsafe(entered.set)
            try:
                if not release.wait(5):
                    raise TimeoutError()
                return publish(*args)
            finally:
                exited.set()
        with patch.object(checkpoints, '_publish', side_effect=blocked):
            task = asyncio.create_task(export_checkpoint_async(self.root / 'cancelled.json',
                self.history, BINDING, self.identity))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    self.assertEqual(self.history.verified_cursor, 65)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertTrue(exited.is_set())
                self.assertFalse(list(self.root.glob('.checkpoint-*')))
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)

    async def test_worker_errors_remain_private(self):
        with patch.object(checkpoints, '_publish', side_effect=OSError('private disk detail')):
            with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
                await export_checkpoint_async(self.root / 'error.json', self.history,
                                               BINDING, self.identity)
