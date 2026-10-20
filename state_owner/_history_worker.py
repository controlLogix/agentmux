"""Keep SQLite reads on their owner loop while an owned worker writes files."""
import asyncio
from concurrent.futures import CancelledError as WorkerCancelled
import threading

from agentmux_contracts import ContractError

PAGE_RECORDS = 32


class _Handoff:
    def __init__(self, history, through):
        self.loop = asyncio.get_running_loop()
        self.owner_thread = threading.get_ident()
        self.source = history.records(through)
        self.count = len(self.source)
        self.source_identity = history.source_identity
        self.verified_cursor = through
        self.total_bytes = history.total_bytes
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.pending = set()
        self.active = set()

    async def _invoke(self, callback, args):
        task = asyncio.current_task()
        self.active.add(task)
        try:
            if self.stopped.is_set():
                raise asyncio.CancelledError()
            return await callback(*args)
        finally:
            self.active.discard(task)

    def call(self, callback, *args):
        if threading.get_ident() == self.owner_thread:
            raise ContractError('owner_worker_thread_invalid')
        if self.stopped.is_set():
            raise WorkerCancelled()
        future = asyncio.run_coroutine_threadsafe(self._invoke(callback, args), self.loop)
        with self.lock:
            self.pending.add(future)
            if self.stopped.is_set():
                future.cancel()
        try:
            return future.result()
        except WorkerCancelled:
            raise asyncio.CancelledError() from None
        finally:
            with self.lock:
                self.pending.discard(future)

    async def _page(self, start):
        return tuple(self.source[index] for index in range(start, min(start + PAGE_RECORDS, self.count)))

    def records(self, through):
        if through != self.verified_cursor:
            raise ContractError('owner_revision_invalid')
        return _Records(self)

    def stop(self):
        self.stopped.set()
        with self.lock:
            for future in tuple(self.pending):
                future.cancel()

    async def join_callbacks(self):
        while self.active:
            await asyncio.gather(*tuple(self.active), return_exceptions=True)


class _Records:
    def __init__(self, handoff):
        self.handoff = handoff

    def __len__(self):
        return self.handoff.count

    def __iter__(self):
        for start in range(0, len(self), PAGE_RECORDS):
            yield from self.handoff.call(self.handoff._page, start)


async def run_history_worker(history, work, *, through=None):
    """Run work(view, call_on_owner) and join it before returning or cancelling.

    Only immutable record pages cross threads. call_on_owner runs a trusted async
    callback on the caller's loop. Cancellation stops new handoffs, cancels pending
    callbacks and joins their cleanup plus the original worker. Blocking file I/O
    may therefore delay cancellation; the caller must keep the cache alive until
    this function exits. A timeout is not evidence that publication was refused.
    """
    cursor = history.verified_cursor if through is None else through
    handoff = _Handoff(history, cursor)
    worker = asyncio.create_task(asyncio.to_thread(work, handoff, handoff.call))
    cancelled = None
    async def join(task):
        nonlocal cancelled
        finished = asyncio.Event()
        task.add_done_callback(lambda _: finished.set())
        while not task.done():
            try:
                # Waiting on a separate signal keeps caller cancellation from
                # cancelling the original task or a shielding future.
                await finished.wait()
            except asyncio.CancelledError as exc:
                cancelled = cancelled or exc
                handoff.stop()
    await join(worker)
    error = None
    try:
        result = worker.result()
    except BaseException as exc:
        error = exc
    # A concurrent Future can report cancellation before its coroutine's
    # async finally block finishes. Keep that cleanup owned as well.
    cleanup = asyncio.create_task(handoff.join_callbacks())
    await join(cleanup)
    cleanup.result()
    if cancelled is not None:
        raise cancelled
    if error is not None:
        raise error
    return result
