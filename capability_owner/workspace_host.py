"""Own an existing repository checkout for a selected workspace reader."""
import asyncio
import os
from pathlib import Path

from agentmux_contracts import ContractError
from hub.fed.code_services import CodeSettings, GitOperations, RepositoryDirectory
from hub.fed.policy import normalize_remote
from hub.store import HubError
from .selected_storage import BoardAuditMirrorHost, SelectedStorageFailure
from .workspace import WorkspaceRoot


class _RepositorySource(BoardAuditMirrorHost):
    """Reuse the existing database executor and protected source custody."""
    @staticmethod
    def _repository_descriptor(repository):
        return type(repository) is dict and set(repository) == {
            'localName', 'repositoryId', 'normalizedRemote'}

    def _tables(self):
        return (('repos', {'repo'}), ('repo_paths', {'repo', 'path'}),
                ('repo_aliases', {'repo', 'alias'}))

    def _admit_policy(self, store, config, policy, remotes):
        repo, rid = self._repository['localName'], self._repository['repositoryId']
        remote = config['repos'].get(repo, {}).get('remote') or remotes.get(repo)
        if (policy.me != self._peer or policy.rid_of(repo) != rid
                or policy.local_of(rid) != repo or remote is None
                or normalize_remote(remote) != self._repository['normalizedRemote']
                or store.q1('SELECT repo FROM repos WHERE repo=?', (repo,)) is None):
            raise ContractError('capability_workspace_unavailable')

class _SelectedRoot(WorkspaceRoot):
    def __init__(self, checkout, host):
        self._host = host
        super().__init__(checkout)

    async def check_current(self):
        await self._host.check_current()

    def check_files(self):
        self._host.check_files()

    def read(self, relative, *, repository_id):
        self.check_files()
        result = super().read(relative, repository_id=repository_id)
        self.check_files()
        return result


class _RepositoryDirectoryOwner:
    def __init__(self, source):
        self._source = source

    @property
    def store(self):
        return self._source._store

    @property
    def hub(self):
        return self

    @property
    def io(self):
        return self._source._executor

    async def db(self, function, *args):
        return await self._source.db(function, *args)


class WorkspaceCheckoutHost:
    """Retain one concrete source, checkout descriptor and original Git jobs.

    Construction receives protected host selection, never request parameters.
    The receiving service must join its original reads before closing this host.
    No repository, worktree, database record or Git reference is created here.
    """
    def __init__(self, pins, *, repository, local_peer, checkout_path, owner_uid,
                 migration_recovery=None, source=None):
        path = Path(checkout_path)
        if not path.is_absolute() or str(path) != os.path.realpath(path):
            raise ContractError('capability_workspace_configuration')
        self._path = str(path)
        self._owns_source = source is None
        if source is not None:
            if (not isinstance(source, BoardAuditMirrorHost) or source._pins != pins
                    or source._peer != local_peer or source._uid != owner_uid
                    or any(source._repository.get(key) != value for key, value in repository.items())):
                raise ContractError('capability_workspace_configuration')
            self._source = source
        else:
            self._source = _RepositorySource(pins, repository=repository,
                local_peer=local_peer, owner_uid=owner_uid,
                migration_recovery=migration_recovery)
        self._repository = dict(repository)
        self._loop = asyncio.get_running_loop()
        self._jobs = set()
        self._closed = False
        self._starting = self._closing = None
        self._checkout = self._directory = self._paths = self._path_identity = None
        self.root = None
        self._record_host = None

    def __repr__(self):
        return '<WorkspaceCheckoutHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('capability_workspace_stale')
        self._source.check_health()

    def check_files(self):
        """Synchronous final disclosure check, also safe in the read worker."""
        try:
            if self._closed or self._source._closed or self.root is None or self.root._fd is None:
                raise ValueError()
            if self._record_host is not None and (self._record_host._closed or not self._record_host._ready):
                raise ValueError()
            self._source._check_files()
            info = os.stat(self._path, follow_symlinks=False)
            if (os.path.realpath(self._path) != self._path
                    or (info.st_dev, info.st_ino) != self._path_identity):
                raise ValueError()
        except Exception:
            raise ContractError('capability_workspace_stale') from None

    async def _paths_now(self):
        return await self._source.db(self._source._store.q,
            'SELECT path FROM repo_paths WHERE repo=? ORDER BY path',
            (self._repository['localName'],))

    async def _resolve(self):
        self._open()
        try:
            checkout = await self._directory.checkout(self._repository['localName'],
                self._path, self._repository['repositoryId'])
        except HubError:
            raise ContractError('capability_workspace_unavailable') from None
        self._open()
        if (checkout.path != self._path
                or normalize_remote(checkout.url) != self._repository['normalizedRemote']):
            raise ContractError('capability_workspace_stale')
        return checkout

    async def _owned(self, coroutine):
        if len(self._jobs) >= 32:
            coroutine.close()
            raise ContractError('capability_workspace_unavailable')
        task = asyncio.create_task(coroutine)
        self._jobs.add(task)
        def finished(done):
            self._jobs.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        try:
            await asyncio.wait({task})
            return task.result()
        finally:
            if task.done():
                self._jobs.discard(task)

    async def _start(self):
        if self._owns_source:
            await self._source.start()
        self._open()
        remote = self._source._policy.cfg['federation'].get('code_remote') or 'origin'
        directory_owner = _RepositoryDirectoryOwner(self._source)
        self._directory = RepositoryDirectory(directory_owner,
            GitOperations(directory_owner), CodeSettings(remote))
        before = os.stat(self._path, follow_symlinks=False)
        self._path_identity = (before.st_dev, before.st_ino)
        self._paths = await self._paths_now()
        self._checkout = await self._resolve()
        self._open()
        self.root = _SelectedRoot(self._checkout, self)
        opened = os.fstat(self.root._fd)
        if (opened.st_dev, opened.st_ino) != self._path_identity:
            raise ContractError('capability_workspace_stale')
        await self._check_current()

    async def start(self):
        if self._starting is not None or self._closed:
            raise ContractError('capability_workspace_stale')
        self._starting = asyncio.create_task(self._owned(self._start()))
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
        except asyncio.CancelledError:
            # Preserve every provisional resource for close, including a late
            # Git result after the startup caller has been cancelled.
            self._closed = True
            raise
        except Exception as error:
            self._closed = True
            raise SelectedStorageFailure('capability_workspace_unavailable', self, error) from None

    async def _check_current(self):
        self._open()
        self.check_files()
        if await self._paths_now() != self._paths or await self._resolve() != self._checkout:
            raise ContractError('capability_workspace_stale')
        self._open()
        self.check_files()

    async def check_current(self):
        self._open()
        return await self._owned(self._check_current())

    async def _cleanup(self):
        if self._starting is not None:
            await asyncio.gather(self._starting, return_exceptions=True)
        if self._jobs:
            await asyncio.gather(*tuple(self._jobs), return_exceptions=True)
        if self.root is not None:
            self.root.close()
        if self._owns_source:
            await self._source.close(timeout=10)

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('capability_cleanup_invalid')
        if asyncio.get_running_loop() is not self._loop:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self)
        self._closed = True
        failed = self._closing is not None and self._closing.done() and (
            self._closing.cancelled() or self._closing.exception() is not None)
        if self._closing is None or failed:
            self._closing = asyncio.create_task(self._cleanup())
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            _, pending = await asyncio.wait({self._closing}, timeout=timeout)
            if pending:
                raise TimeoutError()
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self, error) from None


class WorkspaceReadHost:
    """Serve the selected task owner's checkout without creating another ledger."""
    def __init__(self, selection, *, identity, task, connection, signing_seed,
                 borrowed_sources=()):
        from identity.application_service_selection import ApplicationServiceSelection
        from state_owner.task_host import TaskHost
        if (not isinstance(selection, ApplicationServiceSelection) or not isinstance(task, TaskHost)
                or selection.policy.get('workspace') is None):
            raise ContractError('capability_workspace_configuration')
        self._authority, _ = selection.check_storage_identity_source(identity)
        if (task.ledger._binding != selection.binding('task')
                or task.owner._authority is not self._authority):
            raise ContractError('capability_workspace_configuration')
        self._selection, self._identity, self._task = selection, identity, task
        self._connection, self._seed = connection, signing_seed
        self._loop = asyncio.get_running_loop()
        self._closed = self._ready = False
        self._starting = self._closing = self._service = None
        pin = selection.policy['workspace']
        source = None
        for candidate in borrowed_sources:
            if not isinstance(candidate, BoardAuditMirrorHost):
                raise ContractError('capability_workspace_configuration')
            if candidate._pins['database']['path'] == pin['source']['database']['path']:
                if source is not None:
                    raise ContractError('capability_workspace_configuration')
                source = candidate
        configured = selection.authority_switch_configuration()
        self._checkout = WorkspaceCheckoutHost(pin['source'], repository=pin['repository'],
            local_peer=pin['localPeer'], checkout_path=pin['checkoutPath'],
            owner_uid=os.getuid(), source=source,
            migration_recovery=None if configured is None else configured[1])
        self._checkout._record_host = task

    def __repr__(self):
        return '<WorkspaceReadHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('capability_workspace_stale')
        self._task.check_health()
        authority, _ = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority:
            raise ContractError('capability_workspace_stale')

    async def _start(self):
        from identity.workspace_selection import check_workspace_authority
        from state_owner.ledger import validate_record
        from .resources import RetainedResource
        from .reply_service import CapabilityReplyService
        self._open()
        await check_workspace_authority(self._selection, self._identity)
        self._open()
        pin = self._selection.policy['workspace']
        snapshot = await self._task.ledger.current()
        if snapshot.latest is None:
            raise ContractError('capability_workspace_stale')
        record = validate_record(snapshot.latest.record, self._task.ledger._binding)
        if (record['entityVersion'] < pin['resourceRef']['revision']
                or record['repository'] is None
                or record['repository']['repositoryId'] != pin['repository']['repositoryId']):
            raise ContractError('capability_workspace_stale')
        await self._checkout.start()
        self._open()
        resource = RetainedResource(self._task.ledger._binding, self._task.ledger,
            workspace=self._checkout.root)
        value, receiver = self._selection.policy, pin['receiver']
        service = CapabilityReplyService(self._authority, resources=[resource],
            hub_id=value['kernelScope']['hubId'], profile_id=value['kernelScope']['profileId'],
            authority_id=value['authorityId'], service_id='workspace-owner',
            service_identity_ref=receiver['serviceIdentityRef'], service_instance_id=receiver['serviceInstanceId'],
            signing_key_ref=receiver['issuer']['issuerRef'], signing_seed=self._seed,
            request_signing_key_ref=receiver['requestSigningKeyRef'], connection=self._connection)
        self._service = service
        await service.start()
        await check_workspace_authority(self._selection, self._identity)
        self._open()
        self._ready = True
        self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:
            raise ContractError('capability_workspace_stale')
        self._starting = asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
        except asyncio.CancelledError:
            self._closed = True
            raise
        except Exception as error:
            self._closed = True
            raise SelectedStorageFailure('capability_workspace_unavailable', self, error) from None

    def check_health(self):
        self._open()
        if (not self._ready or self._service is None or self._service._closed
                or self._service._subscription is None or self._connection.is_connected is not True):
            raise ContractError('capability_workspace_stale')
        self._checkout.check_files()

    def fence(self):
        self._closed, self._ready = True, False
        if self._service is not None:
            self._service._closed = True

    async def _cleanup(self):
        if self._starting is not None:
            if not self._starting.done():
                self._starting.cancel()
            await asyncio.gather(self._starting, return_exceptions=True)
        if self._service is not None:
            try:
                await self._service.close(timeout=10)
            except ContractError as error:
                if str(error) != 'capability_cleanup_incomplete' or self._service._cleanup_task is None:
                    raise
                await asyncio.gather(self._service._cleanup_task)
        await self._checkout.close(timeout=10)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('capability_cleanup_invalid')
        if asyncio.get_running_loop() is not self._loop:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self)
        self.fence()
        failed = self._closing is not None and self._closing.done() and (
            self._closing.cancelled() or self._closing.exception() is not None)
        if self._closing is None or failed:
            self._closing = asyncio.create_task(self._cleanup())
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            _, pending = await asyncio.wait({self._closing}, timeout=timeout)
            if pending:
                raise TimeoutError()
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self, error) from None
