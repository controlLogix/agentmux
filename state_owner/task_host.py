"""Enrolled task service, indexed recovery and original resource ownership."""
import asyncio
import time
import uuid

from agentmux_contracts import ContractError
from .artifacts import OwnerArtifacts
from .backup_host import BackupHost
from .backup_lifecycle import OwnerBackupLifecycle, _join
from .checkpoint_host import CheckpointHost
from .checkpoints import CheckpointCadence, CheckpointReceipt, export_checkpoint_async
from .history import OwnerHistory
from .ledger import OwnerLedger, owner_subject
from .task import TaskOwner
from .task_artifact_custody import TaskArtifactCustody
from .task_service import TaskService


class _TaskBackupLifecycle(OwnerBackupLifecycle):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._task_jobs = set()

    async def _drain(self):
        for task in (self._startup, self._loop_task):
            if task is not None:
                try:
                    await _join(task)
                except Exception:
                    # The original task retains its business failure. All of
                    # its workers/readers have joined before _join raises; that
                    # failure is not an unfinished resource or a backup receipt.
                    if not task.done():
                        raise
        for job in tuple(self._task_jobs):
            try:
                await _join(job)
            except Exception:
                if not job.done():
                    raise
        async with self._work_lock:
            pass

    async def run_due(self):
        if self._closed:
            raise ContractError('owner_backup_lifecycle_closed')
        job = asyncio.create_task(self._run_task_due())
        self._task_jobs.add(job)
        try:
            return await _join(job)
        finally:
            self._task_jobs.discard(job)

    async def _run_task_due(self):
        # Include durable commits whose replies were lost before exporting the
        # verified prefix. Reading history never dispatches their retained offers.
        if self._task_custody is None:
            await self._task_ledger.current()
        else:
            await self._task_custody.refresh(max_artifacts=self._max_artifacts, max_total_bytes=self._max_total)
        return await super().run_due()


class TaskHost:
    def __init__(self, authority, ledger, *, ingress, connection, history, checkpoint_host,
                 backup_host, backup_key_id, issuer_ref, signing_seed, service_identity_ref,
                 service_instance_id, requester_reply_prefix, account_public_key,
                 jetstream_domain=None, artifacts=None, artifact_reader=None,
                 monotonic=time.monotonic, clock=time.time):
        if (not isinstance(ledger, OwnerLedger) or not ledger.completion_budget_required
                or not isinstance(history, OwnerHistory) or ledger._history is not history
                or not isinstance(checkpoint_host, CheckpointHost) or not isinstance(backup_host, BackupHost)
                or checkpoint_host.binding != ledger._binding or checkpoint_host.stream != ledger._stream
                or checkpoint_host.stream_identity.created != ledger._identity.created
                or backup_host.binding != ledger._binding or backup_host.stream_identity.created != ledger._identity.created
                or not callable(monotonic)):
            raise ContractError('task_host_configuration')
        self.ledger, self._history = ledger, history
        self._checkpoint, self._monotonic = checkpoint_host, monotonic
        self.owner = TaskOwner(authority, ledger)
        self.service = TaskService(self.owner, ingress, connection=connection,
            service_identity_ref=service_identity_ref, service_instance_id=service_instance_id,
            signing_key_ref=issuer_ref, signing_seed=signing_seed,
            requester_reply_prefix=requester_reply_prefix, account_public_key=account_public_key,
            jetstream_domain=jetstream_domain)
        self.service._host = self
        self._artifact_custody = None
        if artifacts is not None or artifact_reader is not None:
            prefix = '$JS.API' if jetstream_domain is None else '$JS.'+jetstream_domain+'.API'
            if (type(artifacts) is not OwnerArtifacts or type(artifact_reader) is not dict
                    or not {'transport_ref', 'grant_ref'} <= set(artifact_reader)
                    or set(artifact_reader)-{'transport_ref', 'grant_ref', 'approvals_by_operation'}
                    or getattr(artifacts._js, '_nc', None) is not connection
                    or getattr(artifacts._js, '_prefix', None) != prefix
                    or getattr(artifacts._store, '_js', None) is not artifacts._js
                    or getattr(artifacts._store, '_name', None) != artifacts._bucket):
                raise ContractError('task_artifacts_configuration')
            self._artifact_custody = TaskArtifactCustody(self.service, artifacts, **artifact_reader)
        self._backup = _TaskBackupLifecycle(history, ledger._binding, ledger._identity, backup_host,
            key_id=backup_key_id, retrieve_artifact=self._retrieve_artifact, clock=clock)
        self._backup._task_ledger = ledger
        self._backup._task_custody = self._artifact_custody
        self._cadence = CheckpointCadence(now=monotonic())
        self._startup = self._closing = self._timer = self._checkpoint_work = None
        self._closed = self._ready = False
        self._stop, self.done = asyncio.Event(), asyncio.Event()

    @classmethod
    def from_enrolled_host(cls, connection, *, authority, ingress, stream, binding,
                           stream_identity, retention, history, jetstream_domain=None, **resources):
        js = connection.jetstream() if jetstream_domain is None else connection.jetstream(domain=jetstream_domain)
        ledger = OwnerLedger(js, stream=stream, subject=owner_subject(binding), binding=binding,
            retention=retention, stream_identity=stream_identity, history=history, require_completion_budget=True)
        return cls(authority, ledger, ingress=ingress, connection=connection, history=history,
            jetstream_domain=jetstream_domain, **resources)

    def __repr__(self):
        return '<TaskHost private>'

    @property
    def subject(self):
        return self.service.subject

    def check_health(self):
        if self._closed or not self._ready:
            raise ContractError('task_host_unavailable')
        self._backup.check()
        for task in (self._startup, self._timer, self._checkpoint_work):
            if task is not None and task.done():
                task.result()

    async def _retrieve_artifact(self, reference):
        if self._artifact_custody is None:
            raise ContractError('task_backup_artifact_unavailable')
        return await self._artifact_custody.retrieve(reference)

    async def _start(self):
        self.ledger.require_recovery_identity(await self._checkpoint.recovery_identity())
        self.ledger.require_recovery_identity(await self._backup.recovery_identity())
        while not self._closed:
            if (await self.ledger.prepare_history()).ready:
                break
            await asyncio.sleep(0)
        snapshot = await self.ledger.current()
        if snapshot.latest is None:
            raise ContractError('task_not_found')
        self.owner._retained(snapshot.latest)
        if self._closed:
            raise ContractError('task_host_unavailable')
        await self._backup.start()
        if self._closed:
            raise ContractError('task_host_unavailable')
        await self.service.start()
        if self._closed:
            raise ContractError('task_host_unavailable')
        self._timer = asyncio.create_task(self._checkpoint_loop())
        self._ready = True
        self._checkpoint_if_due()

    async def start(self):
        if self._closed or self._startup is not None:
            raise ContractError('task_host_unavailable')
        self._startup = asyncio.create_task(self._start())
        await asyncio.shield(self._startup)

    async def handle(self, raw, *, received_reply_subject):
        self.check_health()
        try:
            return await self.service.handle(raw, received_reply_subject=received_reply_subject)
        finally:
            self._checkpoint_if_due()

    def _checkpoint_if_due(self):
        if self._closed or not self._ready:
            return
        if self._checkpoint_work is not None:
            if not self._checkpoint_work.done():
                return
            self._checkpoint_work.result()
        cursor = self._history.verified_cursor
        if self._cadence.due(cursor, self._monotonic()):
            self._checkpoint_work = asyncio.create_task(self._export_checkpoint(cursor))

    async def _export_checkpoint(self, cursor):
        prefix = self._checkpoint.checkpoint_prefix
        path = prefix.with_name(prefix.name+'.'+str(cursor)+'.'+uuid.uuid4().hex+'.json')
        digest = await export_checkpoint_async(path, self._history, self.ledger._binding,
            self.ledger._identity, through=cursor)
        await self._checkpoint.committed(CheckpointReceipt(str(path), digest, cursor))
        self._cadence.completed(cursor, self._monotonic())

    async def _checkpoint_loop(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), 30)
            except asyncio.TimeoutError:
                self._checkpoint_if_due()

    async def _close(self):
        self._stop.set()
        if self._startup is not None:
            if not self._startup.done():
                self._startup.cancel()
            await asyncio.gather(self._startup, return_exceptions=True)
        failures = []
        try:
            await self.service.close(timeout=None)
        except BaseException as error:
            failures.append(error)
        for task in (self._timer, self._checkpoint_work):
            if task is not None:
                try:
                    await asyncio.shield(task)
                except BaseException as error:
                    failures.append(error)
        try:
            await self._backup.close()
        except BaseException as error:
            failures.append(error)
        if failures:
            raise BaseExceptionGroup('private task host cleanup', failures)
        self.done.set()

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('task_host_cleanup_incomplete')
        self._closed = True
        self._ready = False
        self.service._closed = True
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('task_host_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('task_host_cleanup_incomplete') from None
