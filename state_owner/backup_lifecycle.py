"""Owned hourly backup and daily fenced restore sampling for one live owner."""
import asyncio
import math
from pathlib import Path
import re
import tempfile
import time

from agentmux_contracts import ContractError
from ._history_worker import run_history_worker
from .backup import export_backup, restore_backup, MAX_TOTAL, MAX_ARTIFACTS
from .backup_host import BackupHost
from .history import OwnerHistory
from .ledger import OwnerBinding, StreamIdentity

BACKUP_SECONDS = 3600
SAMPLE_SECONDS = 86400
POLL_SECONDS = 30


async def _join(task):
    finished = asyncio.Event()
    task.add_done_callback(lambda _: finished.set())
    cancelled = None
    while not task.done():
        try:
            await finished.wait()
        except asyncio.CancelledError as exc:
            # The original task keeps ownership of its workers and readers.
            cancelled = cancelled or exc
    try:
        result = task.result()
    except BaseException:
        if cancelled is not None:
            raise cancelled
        raise
    if cancelled is not None:
        raise cancelled
    return result


class OwnerBackupLifecycle:
    """Attach after history recovery; close before closing the shared history.

    The trusted host explicitly enrolls a key and selects protected destinations.
    This service never creates a missing key. It backs up an available owner
    immediately when due, then checks every 30 seconds. Daily samples start again
    after a process restart and restore into disposable fenced storage. These
    intervals are behavior, not measured recovery objectives or disk protection.
    """
    def __init__(self, history, binding, stream_identity, host, *, key_id,
                 retrieve_artifact, max_total_bytes=1_073_741_824, max_artifacts=1024,
                 clock=time.time):
        if (not isinstance(host, BackupHost) or not isinstance(history, OwnerHistory)
                or not isinstance(binding, OwnerBinding) or not isinstance(stream_identity, StreamIdentity)
                or history.binding != binding or host.binding != binding
                or history.source_identity.created != stream_identity.created
                or host.stream_identity.created != stream_identity.created
                or not isinstance(key_id, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', key_id)
                or not callable(retrieve_artifact) or not callable(clock)
                or type(max_total_bytes) is not int or not 1 <= max_total_bytes <= MAX_TOTAL
                or type(max_artifacts) is not int or not 0 <= max_artifacts <= MAX_ARTIFACTS):
            raise ContractError('owner_backup_lifecycle_configuration')
        self._history, self._binding, self._identity = history, binding, stream_identity
        self._host, self._key_id = host, key_id
        self._retrieve, self._clock = retrieve_artifact, clock
        self._max_total, self._max_artifacts = max_total_bytes, max_artifacts
        self._last_sample = None
        self._last_clock = None
        self._retained_floor = max(stream_identity.minimum_sequence,
            history.source_identity.minimum_sequence, host.stream_identity.minimum_sequence)
        self._lock, self._work_lock = asyncio.Lock(), asyncio.Lock()
        self._stop = asyncio.Event()
        self._closed = False
        self._startup = self._loop_task = self._closing = None

    def __repr__(self):
        return '<OwnerBackupLifecycle private>'

    def _now(self):
        try:
            now = self._clock()
        except Exception:
            raise ContractError('owner_backup_clock_invalid') from None
        if (type(now) not in (int, float) or not math.isfinite(now) or now < 0
                or self._last_clock is not None and now < self._last_clock):
            raise ContractError('owner_backup_clock_invalid')
        self._last_clock = now
        return now

    async def _files(self, callback):
        try:
            return await run_history_worker(self._history, lambda view, call: callback())
        except ContractError:
            raise
        except Exception:
            raise ContractError('owner_backup_host_unavailable') from None

    def check(self):
        """Surface a terminal backup failure to the owning service's health path."""
        if self._closed:
            raise ContractError('owner_backup_lifecycle_closed')
        for task in (self._startup, self._loop_task):
            if task is not None and task.done():
                task.result()
        self._require_recovered_floor()

    def _retain_inventory(self, latest):
        if latest is not None:
            if latest.source_identity.created != self._identity.created:
                raise ContractError('owner_recovery_required')
            self._retained_floor = max(self._retained_floor, latest.receipt.cursor,
                                       latest.source_identity.minimum_sequence)

    def _require_recovered_floor(self):
        if self._history.verified_cursor < self._retained_floor:
            raise ContractError('owner_recovery_required')

    async def recovery_identity(self):
        """Return the strongest trusted floor, even before cache replay.

        The host must pass this to OwnerLedger.require_recovery_identity before
        prepare_history or any command admission. This read does not establish
        readiness; start and each tick separately require a recovered cache.
        """
        async with self._work_lock:
            if self._closed:
                raise ContractError('owner_backup_lifecycle_closed')
            latest = await self._files(self._host.latest)
            self._retain_inventory(latest)
            return StreamIdentity(self._identity.created, self._retained_floor)

    async def run_due(self):
        """Run one serialized host tick; completion includes durable inventory."""
        async with self._work_lock:
            if self._closed:
                raise ContractError('owner_backup_lifecycle_closed')
            latest = await self._files(self._host.latest)
            self._retain_inventory(latest)
            self._require_recovered_floor()
            if self._history.verified_cursor == 0:
                return None
            now = self._now()
            floor = self._retained_floor
            if (latest is not None and now < latest.completed_at
                    or self._last_sample is not None and now < self._last_sample):
                raise ContractError('owner_backup_clock_invalid')
            if (latest is None or now - latest.completed_at >= BACKUP_SECONDS
                    or latest.receipt.cursor < floor or latest.key_id != self._key_id):
                key = await self._files(lambda: self._host.load_key(self._key_id))
                try:
                    receipt = await export_backup(self._host.backup_directory, self._history,
                        self._binding, self._identity, key=key, retrieve_artifact=self._retrieve,
                        max_total_bytes=self._max_total, max_artifacts=self._max_artifacts)
                finally:
                    del key
                completed_at = self._now()
                if completed_at < now:
                    raise ContractError('owner_backup_clock_invalid')
                committed = await self._files(lambda: self._host.commit(
                    receipt, key_id=self._key_id, completed_at=completed_at))
                self._retain_inventory(committed)
                # A concurrent completed backup can already carry a newer floor.
                latest = await self._files(self._host.latest)
                if latest is None:
                    raise ContractError('backup_inventory_unavailable')
                self._retain_inventory(latest)
                self._require_recovered_floor()
                floor = self._retained_floor
                # Equal-clock inventory ties may select another complete backup
                # of this same prefix. Sample the just-committed selected key.
                if (latest.receipt.cursor == committed.receipt.cursor
                        and latest.completed_at <= committed.completed_at):
                    latest = committed
            now = self._now()
            if latest is not None and now < latest.completed_at:
                raise ContractError('owner_backup_clock_invalid')
            if self._last_sample is None or now - self._last_sample >= SAMPLE_SECONDS:
                maximum_history = self._history.max_bytes
                def sample():
                    key = self._host.load_key(latest.key_id)
                    try:
                        with tempfile.TemporaryDirectory(prefix='amx-backup-sample-') as directory:
                            folder = Path(directory).resolve()
                            if folder.is_relative_to(Path(self._host.backup_directory).resolve()):
                                raise ContractError('owner_backup_sample_failed')
                            identity = StreamIdentity(self._identity.created,
                                max(floor, latest.source_identity.minimum_sequence))
                            with restore_backup(self._host.backup_directory, latest.receipt.manifest_name,
                                    expected_digest=latest.receipt.digest, key=key, binding=self._binding,
                                    stream_identity=identity, history_path=folder / 'sample.sqlite',
                                    max_total_bytes=self._max_total, max_artifacts=self._max_artifacts,
                                    max_history_bytes=maximum_history) as restored:
                                if not restored.reconciliation_required or restored.cursor != latest.receipt.cursor:
                                    raise ContractError('owner_backup_sample_failed')
                    finally:
                        del key
                await self._files(sample)
                sampled_at = self._now()
                if sampled_at < now:
                    raise ContractError('owner_backup_clock_invalid')
                self._last_sample = sampled_at
            return latest

    async def _start(self):
        def verify_enrollment():
            self._host.load_key(self._key_id)
        await self._files(verify_enrollment)
        await self.run_due()
        if self._closed:
            raise ContractError('owner_backup_lifecycle_closed')
        self._loop_task = asyncio.create_task(self._loop())

    async def start(self):
        async with self._lock:
            if self._closed or self._startup is not None:
                raise ContractError('owner_backup_lifecycle_invalid')
            self._startup = asyncio.create_task(self._start())
        await _join(self._startup)

    async def _loop(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), POLL_SECONDS)
            except asyncio.TimeoutError:
                if not self._closed:
                    await self.run_due()

    async def _drain(self):
        error = None
        for task in (self._startup, self._loop_task):
            if task is not None:
                try:
                    await _join(task)
                except BaseException as exc:
                    if not (isinstance(exc, ContractError)
                            and exc.code == 'owner_backup_lifecycle_closed' and self._closed):
                        error = error or exc
        # Also join a direct host tick before releasing the shared cache.
        async with self._work_lock:
            pass
        if error is not None:
            raise error

    async def close(self):
        async with self._lock:
            self._closed = True
            self._stop.set()
            if self._closing is None:
                self._closing = asyncio.create_task(self._drain())
        await _join(self._closing)
