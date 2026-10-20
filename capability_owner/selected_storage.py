"""Installed storage composition; owner resources never become plugin context."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import os
import re
import threading
import tomllib
import time
import uuid

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.board_services import SharedBoardStore
from hub.fed.config import DEFAULTS
from hub.fed.policy import Policy, normalize_remote
from hub.fed.runtime import Federation
from hub.store import Store
from hub.nats_transport import new_client
from hub.fed.session import FederationSession
from identity.application_enrollment import _read_material
from identity.application_service_selection import ApplicationServiceSelection
from state_owner.backup_host import BackupHost
from state_owner.backup_lifecycle import OwnerBackupLifecycle, _join
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import CheckpointCadence, CheckpointReceipt, export_checkpoint_async
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from .board_allocation import BoardAllocationResource, BoardAllocationTarget
from .board_allocation_journal import BoardAllocationJournal
from .board_allocation_owner import BoardAllocationOwner
from .board_journal import BoardOperationJournal
from .board_owner import BoardActor, BoardMutationOwner
from .board_phase_signer import BoardPhaseSigner
from .board_target import BoardTargetBinding
from .board_publisher import BoardPublisher
from .federation_board import FederationBoardResource
from .private_storage import PrivateStorageResource
from .reply_service import CapabilityReplyService


class SelectedStorageFailure(ContractError):
    """Keep the original owner and private cause reachable for later cleanup."""
    def __init__(self, code, owner, cause=None):
        super().__init__(code)
        self.owner, self._cause = owner, cause

    def __repr__(self):
        return '<SelectedStorageFailure private>'


def _file_identity(path, *, mutable=False):
    meta = os.stat(path, follow_symlinks=False)
    identity = (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid)
    return identity if mutable else (*identity, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


@dataclass(frozen=True, repr=False)
class _PublisherBoardDomain:
    _audit: object = field(repr=False)
    _publisher: object = field(repr=False)
    session: object = field(repr=False)
    js: object = field(repr=False)

    @property
    def me(self):
        return self._audit._peer

    @property
    def policy(self):
        return self._audit._policy_for(self._publisher)

    @property
    def store(self):
        return self._audit._store

    async def db(self, function, *args, **kwargs):
        return await self._audit.db(function, *args, **kwargs)

    def sender_of(self, caller):
        # This preserves retained attribution parsing, never authentication.
        return Federation.sender_of(self, caller)


class BoardAuditMirrorHost:
    """Own one existing Store and its single joined database executor.

    No card watcher, database migration, federation runtime or broker credential
    is created here. Each board view uses its selected publisher's real session.
    """
    def __init__(self, pins, *, repository, local_peer, owner_uid,
                 migration_recovery=None):
        self._pins = strict_loads(canonical_bytes(pins))
        self._repository = strict_loads(canonical_bytes(repository))
        if (type(pins) is not dict or set(pins) != {'database', 'policy'}
                or set(pins['database']) != {'path', 'applicationId', 'userVersion'}
                or set(pins['policy']) != {'path', 'sha256'}
                or not self._repository_descriptor(repository)
                or type(local_peer) is not str or not local_peer
                or type(owner_uid) is not int or owner_uid != os.getuid()):
            raise ContractError('selected_board_projection_invalid')
        self._peer, self._uid = local_peer, owner_uid
        self._migration_recovery = migration_recovery
        self._loop = asyncio.get_running_loop()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='selected-board-db')
        self._store = self._policy = self._database_identity = self._policy_identity = None
        self._failed_custody = None
        self._pending = set()
        self._worker = threading.local()
        self._starting = self._closing = None
        self._closed = False
        self._policy_transition = None
        self._policy_paused = self._policy_replacing = self._policy_suspended = False
        self._policy_generation = 0
        self._opening_policy = None
        self._resource_bootstraps = set()
        self._resource_bootstrap_calls = set()

    def __repr__(self):
        return '<BoardAuditMirrorHost private>'

    @staticmethod
    def _repository_descriptor(repository):
        return type(repository) is dict and set(repository) == {'localName', 'repositoryId', 'normalizedRemote', 'counterPrefix'}

    def _tables(self):
        return (('p_board_cards', {'rid', 'key', 'repo', 'card', 'rev', 'status', 'assignee',
            'updated_by', 'updated_at', 'deleted'}),
            ('fed_audit', {'seq', 'at', 'dir', 'plane', 'peer', 'rid', 'subject', 'msg_id',
                'sha', 'size', 'decision', 'detail'}))

    def _remotes(self, store):
        repo = self._repository['localName']
        alias = store.q1("SELECT alias FROM repo_aliases WHERE repo=? AND alias LIKE '%/%' ORDER BY rowid LIMIT 1", (repo,))
        return {} if alias is None else {repo: normalize_remote(alias['alias'])}

    def _admit_policy(self, store, config, policy, remotes):
        repo, rid = self._repository['localName'], self._repository['repositoryId']
        remote = config['repos'].get(repo, {}).get('remote') or remotes.get(repo)
        if (policy.me != self._peer or policy.rid_of(repo) != rid or policy.local_of(rid) != repo
                or policy.board_prefix(repo) != self._repository['counterPrefix']
                or remote is None or normalize_remote(remote) != self._repository['normalizedRemote']
                or store.q1('SELECT repo FROM repos WHERE repo=?', (repo,)) is None):
            raise ContractError('selected_board_projection_invalid')

    def _open_existing(self):
        store = None
        try:
            selected = self._pins['database']
            store = Store.open_existing(selected['path'], application_id=selected['applicationId'],
                user_version=selected['userVersion'], owner_uid=self._uid,
                migration_recovery=self._migration_recovery)
            # Keep provisional ownership before schema or policy checks can fail.
            self._store = store
            for table, columns in self._tables():
                present = {row['name'] for row in store.q('PRAGMA table_info(' + table + ')')}
                if not columns <= present:
                    raise ContractError('selected_board_projection_invalid')
            source = self._pins['policy']
            before = _file_identity(source['path'])
            raw = _read_material(source['path'], max_bytes=65536, return_bytes=True)
            opening = self._opening_policy
            if opening is None:
                admitted = 'sha256:' + hashlib.sha256(raw).hexdigest() == source['sha256']
            else:
                transition, expected, identity = opening
                self._transition_owner(transition)
                admitted = self._policy_paused and raw == expected and before == identity
            if before != _file_identity(source['path']) or not admitted:
                raise ContractError('selected_board_projection_invalid')
            config = tomllib.loads(raw.decode('utf-8'))
            config = {'federation': {**DEFAULTS, **config.get('federation', {})},
                'repos': config.get('repos', {}), 'peers': config.get('peers', {})}
            remotes = self._remotes(store)
            policy = Policy(config, remotes)
            if opening is None:
                self._admit_policy(store, config, policy, remotes)
            else:
                policy, self._policy_suspended = self._policy_candidate(transition, raw)
            self._store, self._policy = store, policy
            self._database_identity = _file_identity(selected['path'], mutable=True)
            self._policy_identity = before
        except BaseException as error:
            if getattr(error, 'owner', None) is not None:
                self._failed_custody = error.owner
            raise

    async def _submit(self, function, *args, _admit_store=False, **kwargs):
        def owned_operation():
            self._worker.active = True
            try:
                if _admit_store:
                    self._store.check_existing()
                return function(*args, **kwargs)
            finally:
                self._worker.active = False
        future = self._loop.run_in_executor(self._executor, owned_operation)
        self._pending.add(future)
        try:
            await asyncio.wait({future})
            return future.result()
        except asyncio.CancelledError:
            # A cancelled await does not roll back the original SQL transaction.
            while not future.done():
                try:
                    await asyncio.wait({future})
                except asyncio.CancelledError:
                    continue
            if not future.cancelled():
                future.exception()
            raise
        finally:
            if future.done():
                self._pending.discard(future)

    async def start(self):
        if self._closed or self._starting is not None or asyncio.get_running_loop() is not self._loop:
            raise ContractError('selected_board_projection_unavailable')
        self._starting = asyncio.create_task(self._submit(self._open_existing))
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
            self.check_health()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.fence()
            raise SelectedStorageFailure('selected_board_projection_unavailable', self, error) from None

    def _check_files(self):
        if (self._store is None
                or self._database_identity != _file_identity(self._pins['database']['path'], mutable=True)
                or (not (self._policy_paused and self._policy_replacing)
                    and self._policy_identity != _file_identity(self._pins['policy']['path']))):
            raise ContractError('selected_board_projection_unavailable')

    def _bind_policy_transition(self, transition):
        from .federation_policy_transition import FederationPolicyTransition
        if (type(transition) is not FederationPolicyTransition
                or self._policy_transition is not None or self._closed):
            raise ContractError('selected_policy_transition_invalid')
        self._policy_transition = transition

    def _transition_owner(self, transition):
        if transition is not self._policy_transition or self._closed:
            raise ContractError('selected_policy_transition_invalid')

    async def _recover_policy_start(self, transition, raw, identity):
        self._transition_owner(transition)
        if self._starting is not None or self._store is not None:
            raise ContractError('selected_policy_transition_invalid')
        self._policy_paused = True
        self._opening_policy = (transition, raw, identity)
        # Invoke the real subtype's opening path, including its FTS, trigger and
        # schema checks. Only the policy admission has the retained override.
        self._starting = asyncio.create_task(self._submit(self._open_existing))
        def settled(done):
            self._opening_policy = None
            if not done.cancelled():
                done.exception()
        self._starting.add_done_callback(settled)
        await asyncio.wait({self._starting})
        self._starting.result()
        self._transition_owner(transition)
        self.check_health()

    async def _pause_policy(self, transition):
        self._transition_owner(transition)
        self.check_health()
        # No await separates refusal of new admissions from this pending set.
        self._policy_paused = True
        pending = tuple(self._pending)
        if pending:
            await asyncio.wait(pending)
            for original in pending:
                original.result()
        self._transition_owner(transition)
        self.check_health()

    def _policy_candidate(self, transition, raw):
        self._transition_owner(transition)
        if not self._policy_paused:
            raise ContractError('selected_policy_transition_invalid')
        self._store.check_existing()
        config = tomllib.loads(raw.decode('utf-8'))
        config = {'federation': {**DEFAULTS, **config.get('federation', {})},
            'repos': config.get('repos', {}), 'peers': config.get('peers', {})}
        remotes = self._remotes(self._store)
        policy = Policy(config, remotes)
        if self._repository is None:
            self._admit_policy(self._store, config, policy, remotes)
            return policy, False
        repo = self._repository['localName']
        suspended = repo not in config['repos']
        if suspended:
            if (policy.me != self._peer or policy.rid_of(repo) is not None
                    or self._store.q1('SELECT repo FROM repos WHERE repo=?', (repo,)) is None):
                raise ContractError('selected_policy_transition_invalid')
        else:
            self._admit_policy(self._store, config, policy, remotes)
        return policy, suspended

    def _begin_policy_projection(self, transition):
        self._transition_owner(transition)
        if not self._policy_paused or self._pending:
            raise ContractError('selected_policy_transition_invalid')
        self.check_health()
        # Old SQL has joined. Health can stay available during this controlled
        # replacement, but no storage admission can observe the intermediate file.
        self._policy_replacing = True

    def _install_policy_generation(self, transition, candidate, identity, revision):
        self._transition_owner(transition)
        if not self._policy_paused or not self._policy_replacing or self._pending:
            raise ContractError('selected_policy_transition_invalid')
        self._policy, self._policy_suspended = candidate
        self._policy_identity = identity
        self._policy_generation = revision
        self._policy_replacing = False
        self._policy_paused = False
        self.check_health()

    def _resume_old_policy(self, transition):
        self._transition_owner(transition)
        if self._policy_replacing:
            raise ContractError('selected_policy_transition_pending')
        self.check_health()
        self._policy_paused = False

    async def _resource_bootstrap(self, transition, declaration):
        """Issue structural startup access after the same service projection."""
        from .policy_bootstrap import _issue
        self._transition_owner(transition)
        host = transition._selected_host
        original = {'source': self._pins, 'repository': self._repository, 'localPeer': self._peer}
        task = asyncio.current_task()
        def selected():
            self._transition_owner(transition)
            transition._available()
            if (host is None or host._starting is not task or host._ready
                    or transition not in host._policy_transitions or self not in transition._sources
                    or declaration not in ('board', 'messages', 'knowledge', 'code', 'work')
                    or host._preconstructed_sources.get(declaration) is not self
                    or original not in transition.source_bindings or self._store is None
                    or self._policy_generation < 1 or self._policy_paused or self._policy_replacing):
                raise ContractError('selected_policy_bootstrap_refused')
            protected = host._selection.policy['storage'].get(declaration)
            if (protected is None or protected['auditMirror' if declaration == 'board' else 'source'] != self._pins
                    or protected['localPeer'] != self._peer):
                raise ContractError('selected_policy_bootstrap_refused')
            repository = protected['repository']
            if ((repository is None) != (self._repository is None)
                    or repository is not None and any(
                        self._repository.get(key) != value for key, value in repository.items())):
                raise ContractError('selected_policy_bootstrap_refused')
            self._check_files()
        selected()
        if len(self._resource_bootstrap_calls) >= 32:
            raise ContractError('selected_policy_bootstrap_refused')
        finished = self._loop.create_future()
        self._resource_bootstrap_calls.add(finished)
        try:
            proof = await transition._bootstrap_authority()
            selected()
            if self._policy_generation != proof.revision or self._policy_identity != proof.identity:
                raise ContractError('selected_policy_bootstrap_refused')
            permit = _issue(self, host, transition, declaration)
            self._resource_bootstraps.add(permit)
            return permit
        finally:
            self._resource_bootstrap_calls.discard(finished)
            finished.set_result(None)

    def _policy_for(self, publisher):
        if getattr(self._worker, 'active', False):
            # Already admitted SQL must finish while close joins its owner.
            # Only this host's executor enters this thread-local scope.
            self._check_files()
        else:
            self.check_health()
            publisher.check()
        return self._policy

    def check_health(self):
        try:
            if asyncio.get_running_loop() is not self._loop or self._closed:
                raise ValueError()
            self._check_files()
        except Exception:
            self.fence()
            raise ContractError('selected_board_projection_unavailable') from None

    async def db(self, function, *args, **kwargs):
        self.check_health()
        if self._policy_paused:
            raise ContractError('selected_policy_transition_pending')
        if self._policy_suspended:
            raise ContractError('selected_policy_not_shared')
        if len(self._pending) >= 32:
            raise ContractError('selected_board_projection_capacity')
        return await self._submit(function, *args, _admit_store=True, **kwargs)

    def board_for(self, publisher):
        self.check_health()
        if type(publisher) is not BoardPublisher:
            raise ContractError('selected_board_projection_invalid')
        publisher.check()
        return SharedBoardStore(_PublisherBoardDomain(self, publisher, publisher._session, publisher.jetstream))

    def fence(self):
        self._closed = True

    async def _cleanup(self):
        for permit in tuple(self._resource_bootstraps):
            permit.expire()
        if self._resource_bootstrap_calls:
            await asyncio.wait(tuple(self._resource_bootstrap_calls))
        for permit in tuple(self._resource_bootstraps):
            await permit.close()
        if self._starting is not None:
            await asyncio.gather(self._starting, return_exceptions=True)
        if self._pending:
            await asyncio.gather(*tuple(self._pending), return_exceptions=True)
        if self._store is not None:
            await self._submit(self._store.db.close)
            self._store = None
        if self._failed_custody is not None:
            await self._submit(self._failed_custody.close)
            self._failed_custody = None
        # Joining shutdown in another thread keeps the loop available to owners.
        await asyncio.to_thread(self._executor.shutdown, wait=True)

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('selected_board_projection_cleanup_invalid')
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
            raise SelectedStorageFailure('selected_board_projection_cleanup_incomplete', self, error) from None


def _stream_identity(value):
    return StreamIdentity(datetime.fromisoformat(value['created']), value['minimumSequence'])


async def _join_terminal(task):
    try:
        await _join(task)
    except BaseException:
        if not task.done() or asyncio.current_task().cancelling():
            raise
        # The task retains its original failure. A joined failed operation is
        # neither a backup receipt nor an unfinished resource.


class _StorageBackupLifecycle(OwnerBackupLifecycle):
    def __init__(self, *args, ledger, **kwargs):
        super().__init__(*args, **kwargs)
        self._ledger = ledger
        self._jobs = set()

    async def run_due(self):
        if self._closed:
            raise ContractError('owner_backup_lifecycle_closed')
        job = asyncio.create_task(self._refresh_due())
        self._jobs.add(job)
        try:
            return await _join(job)
        finally:
            if job.done():
                self._jobs.discard(job)

    async def _refresh_due(self):
        # Include a durable commit whose reply was lost before cache refresh.
        await self._ledger.current()
        return await super().run_due()

    async def _drain(self):
        for task in (self._startup, self._loop_task):
            if task is not None:
                await _join_terminal(task)
        for task in tuple(self._jobs):
            await _join_terminal(task)
        async with self._work_lock:
            pass


class _StorageLedgerCustody:
    """Keep selected recovery floors, checkpoints and backups with one ledger."""
    def __init__(self, ledger, history, checkpoint, backup):
        self.ledger, self.history = ledger, history
        self.checkpoint, self.backup = checkpoint, backup
        self._cadence = CheckpointCadence()
        self._stop = asyncio.Event()
        self._timer = self._export = None

    async def start(self):
        self.ledger.require_recovery_identity(await self.checkpoint.recovery_identity())
        self.ledger.require_recovery_identity(await self.backup.recovery_identity())
        while not (await self.ledger.prepare_history()).ready:
            await asyncio.sleep(0)
        await self.ledger.current()
        await self.backup.start()
        self._timer = asyncio.create_task(self._run())

    async def _checkpoint(self, cursor):
        prefix = self.checkpoint.checkpoint_prefix
        path = prefix.with_name(prefix.name + '.' + str(cursor) + '.' + uuid.uuid4().hex + '.json')
        digest = await export_checkpoint_async(path, self.history, self.ledger._binding,
            self.ledger._identity, through=cursor)
        await self.checkpoint.committed(CheckpointReceipt(str(path), digest, cursor))
        self._cadence.completed(cursor, time.monotonic())

    def check(self):
        self.backup.check()
        for task in (self._timer, self._export):
            if task is not None and task.done():
                task.result()
        cursor = self.history.verified_cursor
        if not self._stop.is_set() and (self._export is None or self._export.done()) and self._cadence.due(cursor, time.monotonic()):
            self._export = asyncio.create_task(self._checkpoint(cursor))

    async def _run(self):
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), 30)
            except TimeoutError:
                self.check()

    async def close(self):
        self._stop.set()
        for task in (self._timer, self._export):
            if task is not None:
                await _join_terminal(task)
        await self.backup.close()


class SelectedStorageHost:
    """Compose only the protected, explicitly selected installed storage owners.

    The identity service remains borrowed. Receiver credentials cannot publish
    ledgers or board keys; each provider keeps its separate publisher connection.
    """
    def __init__(self, selection, *, identity, federation_policy=None):
        if not isinstance(selection, ApplicationServiceSelection) or selection.policy.get('storage') is None:
            raise ContractError('selected_storage_configuration')
        self._selection, self._identity = selection, identity
        self._authority, self._ingress = selection.check_storage_identity_source(identity)
        self._loop = asyncio.get_running_loop()
        self._closed = self._ready = False
        self._starting = self._closing = None
        self._receivers, self._publishers = [], []
        self._peer_control_owners, self._peer_control_publishers = [], []
        self._knowledge_controls = []
        self._work_controls = []
        self._core_work_owners = []
        self._federation_policy = federation_policy
        self._preconstructed_sources = {}
        self._startup_permits = {}
        self._policy_transitions = set()
        self._policy_change = None
        self._board_owners = []
        self._clients, self._sessions, self._connects = [], [], []
        self._histories, self._custody, self._workers = [], [], set()
        self._audit = None
        self._message_stores, self._message_sessions = [], []
        self._work_domains = []
        self._work_lifecycle_owners = []
        self._resources, self._routes = [], []
        configured = selection.authority_switch_configuration()
        self._legacy_recovery = None if configured is None else configured[1]
        if federation_policy is not None:
            from state_owner.configuration_host import ConfigurationHost
            from state_owner.federation_policy import FederationPolicyOwner
            from identity.federation_policy_selection import policy_target
            if (type(federation_policy) is not ConfigurationHost
                    or not isinstance(federation_policy.owner, FederationPolicyOwner)
                    or federation_policy.owner._authority is not self._authority
                    or 'federationPolicy' not in selection.policy
                    or federation_policy.owner.custody.target != policy_target(selection.policy)):
                raise ContractError('selected_storage_configuration')

    async def _prepare_policy_sources(self):
        """Retain every original source before recovering its selected generation."""
        if self._federation_policy is None:
            return
        from .messages_host import MessageStoreHost
        from .knowledge_host import KnowledgeStoreHost
        from .code_host import CodeStoreHost
        from .work_host import WorkStoreHost
        from .federation_policy_transition import FederationPolicyTransition
        storage = self._selection.policy['storage']
        for name, kind in (('board', BoardAuditMirrorHost), ('messages', MessageStoreHost),
                ('knowledge', KnowledgeStoreHost), ('code', CodeStoreHost), ('work', WorkStoreHost)):
            selected = storage.get(name)
            if selected is None or name == 'work' and 'policy' not in selected['source']:
                continue
            pins = selected['auditMirror'] if name == 'board' else selected['source']
            repository = selected['repository']
            source = next((item for item in (self._audit, *self._message_stores)
                if item is not None and item._pins == pins and item._peer == selected['localPeer']
                    and (item._repository == repository or repository is not None
                        and item._repository is not None
                        and all(item._repository.get(key) == value for key, value in repository.items()))), None)
            if source is None:
                source = kind(pins, repository=repository, local_peer=selected['localPeer'],
                    owner_uid=os.getuid(), migration_recovery=self._legacy_recovery)
                if name == 'board':
                    self._audit = source
                else:
                    self._message_stores.append(source)
            self._preconstructed_sources[name] = source
        host = self._federation_policy
        policy = self._selection.policy['federationPolicy']
        sources = tuple(item for item in (self._audit, *self._message_stores) if item is not None
            and item._pins.get('policy') == policy['target']['source']['policy'])
        route = policy['projectionAuthority']
        transition = FederationPolicyTransition(host.owner, sources, selected_host=self,
            requester_reply_prefix=host._reply_prefix, projection_service_ref=route['serviceIdentityRef'],
            projection_transport_ref=route['transportRef'], projection_grant_ref=route['grantRef'])
        host.bind_policy_transition(transition)
        await host.recover_policy_projection()
        for source in dict.fromkeys(self._preconstructed_sources.values()):
            if source._starting is None:
                await source.start()
            else:
                source.check_health()
        for name, source in self._preconstructed_sources.items():
            if source in transition._sources and source._policy_generation > 0:
                self._startup_permits[name] = await source._resource_bootstrap(transition, name)

    async def _startup_db(self, name, function, *args):
        permit = self._startup_permits.get(name)
        if permit is not None:
            return await permit.submit(function, *args)
        source = self._preconstructed_sources.get(name)
        if source is None:
            raise ContractError('selected_storage_configuration')
        return await source.db(function, *args)

    def __repr__(self):
        return '<SelectedStorageHost private>'

    def register_policy_transition(self, transition):
        from .federation_policy_transition import FederationPolicyTransition
        self._open()
        owned = tuple(source for source in (self._audit, *self._message_stores) if source is not None)
        if (type(transition) is not FederationPolicyTransition or transition._selected_host is not self
                or transition._owner._authority is not self._authority
                or any(not any(source is original for original in owned) for source in transition._sources)):
            raise ContractError('selected_policy_transition_invalid')
        self._policy_transitions.add(transition)

    def _policy_gates(self):
        return (*self._receivers, *getattr(self, '_knowledge_controls', ()),
            *getattr(self, '_work_controls', ()), *getattr(self, '_core_work_owners', ()))

    async def pause_policy_transition(self, transition, *, original_operation):
        from .federation_policy_transition import _PolicyPause
        self._open()
        if (transition not in self._policy_transitions or transition._selected_host is not self
                or type(original_operation) is not tuple or len(original_operation) != 2
                or not isinstance(original_operation[0], str)
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', original_operation[0]) is None
                or not isinstance(original_operation[1], str)
                or re.fullmatch(r'sha256:[a-f0-9]{64}', original_operation[1]) is None):
            raise ContractError('selected_policy_transition_invalid')
        if self._policy_change is None:
            transition._available()
            for source in transition._sources:
                source.check_health()
            sources = tuple((source, source._policy_generation, source._database_identity,
                source._policy_identity, source._policy, source._policy_suspended) for source in transition._sources)
            gates = self._policy_gates()
            # Fence every receiver before awaiting any of its original work.
            for service in gates:
                service.begin_policy_pause()
            async def joined():
                snapshot = await transition._owner._ledger.current()
                for service in gates:
                    await service.join_policy_pause()
                workers = {worker for owner in self._board_owners for worker in owner._workers}
                workers.update(worker for owner in self._peer_control_owners for worker in owner._workers)
                if workers:
                    await asyncio.gather(*workers, return_exceptions=True)
                return _PolicyPause(snapshot.sequence,
                    None if snapshot.latest is None else snapshot.latest.record, sources, gates)
            original = asyncio.create_task(joined(), name='selected-policy:original-admissions')
            original.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            self._policy_change = (transition, original_operation, original)
        owner, operation, original = self._policy_change
        if owner is not transition or operation != original_operation:
            raise ContractError('selected_policy_transition_pending')
        await asyncio.shield(original)
        self._open()

    async def resume_policy_transition(self, transition, committed_revision, suspended_repositories):
        self._open()
        transition._available()
        current = self._policy_change
        if (current is None or current[0] is not transition or not current[2].done()
                or current[2].cancelled() or current[2].exception() is not None
                or type(committed_revision) is not int or committed_revision < 1):
            raise ContractError('selected_policy_transition_invalid')
        snapshot = await transition._owner._ledger.current()
        self._open()
        transition._available()
        if (self._policy_change is not current or transition._closed or transition._owner._closed
                or snapshot.sequence != committed_revision or snapshot.latest is None):
            raise ContractError('selected_policy_transition_invalid')
        state = transition._owner._retained(snapshot.latest)
        document = strict_loads(transition._owner._document(state))
        operation = strict_loads(snapshot.latest.record)['operation']
        if (current[1] != (operation['operationId'], operation['payloadDigest'])
                or document['target'] != transition._owner.custody.target.descriptor
                or any(source._policy_generation != committed_revision or source._policy_paused
                    or source._policy_replacing for source in transition._sources)):
            raise ContractError('selected_policy_transition_invalid')
        expected = {source._repository['repositoryId'] for source in transition._sources
            if source._policy_suspended and source._repository is not None}
        if set(suspended_repositories) != expected:
            raise ContractError('selected_policy_transition_invalid')
        for source in transition._sources:
            source.check_health()
        gates = self._policy_gates()
        if (gates != current[2].result().gates
                or any(service._closed or not service._policy_paused for service in gates)):
            raise ContractError('selected_policy_transition_invalid')
        for domain in getattr(self, '_work_domains', ()):
            if domain._source in transition._sources:
                domain._resume_policy(transition)
        for service in gates:
            service.end_policy_pause()
        self._policy_change = None

    async def abort_policy_transition(self, transition):
        """Restore old admissions only after a proved precommit refusal."""
        from .federation_policy_transition import _PolicyPause
        self._open()
        current = self._policy_change
        if (transition not in self._policy_transitions or transition._selected_host is not self
                or current is None or current[0] is not transition or not current[2].done()
                or current[2].cancelled() or current[2].exception() is not None
                or transition._precommit_refusal != current[1]
                or transition._commit_handed_off == current[1]
                or any(not task.done() for task in transition._owner._active)):
            raise ContractError('selected_policy_transition_pending')
        transition._available()
        before = current[2].result()
        if type(before) is not _PolicyPause:
            raise ContractError('selected_policy_transition_invalid')
        # No-commit means the actual transition never entered ConfigurationOwner
        # for this attempt. A missing broker outcome alone is insufficient.
        outcome = await transition._owner._ledger.outcome(*current[1])
        snapshot = await transition._owner._ledger.current()
        self._open()
        transition._available()
        if (self._policy_change is not current or outcome is not None
                or transition._precommit_refusal != current[1]
                or transition._commit_handed_off == current[1]
                or snapshot.sequence != before.revision
                or (None if snapshot.latest is None else snapshot.latest.record) != before.record
                or any(not task.done() for task in transition._owner._active)):
            raise ContractError('selected_policy_transition_pending')
        if tuple(row[0] for row in before.sources) != transition._sources:
            raise ContractError('selected_policy_transition_invalid')
        for source, generation, database, policy_file, policy, suspended in before.sources:
            if (source._policy_generation != generation or source._database_identity != database
                    or source._policy_identity != policy_file or source._policy is not policy
                    or source._policy_suspended != suspended or source._policy_replacing or source._pending):
                raise ContractError('selected_policy_transition_pending')
            source.check_health()
        gates = self._policy_gates()
        if gates != before.gates or any(service._closed or not service._policy_paused for service in gates):
            raise ContractError('selected_policy_transition_pending')
        # The preceding awaits are over. No new work enters while all original
        # source generations and receiver gates are restored together.
        for source in transition._sources:
            source._resume_old_policy(transition)
        for service in gates:
            service.end_policy_pause()
        transition._precommit_refusal = transition._uncertain = None
        self._policy_change = None

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('selected_storage_unavailable')
        authority, ingress = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority or ingress is not self._ingress:
            raise ContractError('selected_storage_unavailable')

    async def _files(self, function, *args, **kwargs):
        self._open()
        worker = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        self._workers.add(worker)
        try:
            result = await _join(worker)
            self._open()
            return result
        finally:
            if worker.done():
                self._workers.discard(worker)

    async def _lost(self, *_args):
        self.fence()

    async def _connect(self, name):
        self._open()
        selected = self._selection.storage_descriptor(name)
        # Revalidate exact credentials on each broker authentication callback.
        await self._files(self._selection.load_storage_credentials, name)
        client = new_client(require_tls=True,
            leaf_certificate_sha256=selected['connection']['leafCertificateSHA256'])
        self._clients.append(client)
        session = FederationSession()
        self._sessions.append(session)
        client._agentmux_session = session

        def signature(nonce):
            credential = self._selection.load_storage_credentials(name)
            key = nkeys.from_seed(credential.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:
                key.wipe()

        options = self._selection.storage_tls_options(name)
        options.update(name='agentmux-' + name + '-storage', allow_reconnect=False,
            max_reconnect_attempts=1, reconnect_time_wait=0, connect_timeout=3,
            dont_randomize=True, no_echo=True, inbox_prefix=selected['credentials']['replyPrefix'],
            user_jwt_cb=lambda: self._selection.load_storage_credentials(name).jwt.encode('ascii'),
            signature_cb=signature, disconnected_cb=self._lost, reconnected_cb=self._lost,
            closed_cb=self._lost, error_cb=self._lost)
        original = asyncio.create_task(client.connect(**options))
        self._connects.append(original)
        async with asyncio.timeout(5):
            await asyncio.shield(original)
        self._open()
        if client.is_connected is not True:
            raise ContractError('selected_storage_unavailable')
        return client

    async def _publisher(self, name):
        selected = self._selection.storage_descriptor(name)
        credential = await self._files(self._selection.read_storage_credentials, name)
        options = self._selection.storage_tls_options(name)
        publisher = BoardPublisher(credentials=credential,
            account_public_key=selected['credentials']['accountPublicKey'],
            user_public_key=selected['credentials']['userPublicKey'],
            server_url=selected['connection']['endpoint'], tls_context=options['tls'],
            leaf_certificate_sha256=selected['connection']['leafCertificateSHA256'],
            server_name=selected['connection']['serverName'], connection_lost=self._lost,
            **self._selection.storage_policy_inputs(name))
        self._publishers.append(publisher)
        await publisher.start()
        self._open()
        return publisher

    async def _ledger(self, name, jetstream):
        value = self._selection.policy
        selected = value['storage']['privateStorage'] if name == 'private' else self._selection.storage_descriptor(name)
        pins, backup_pins = selected['ledger'], selected['backup']
        domain, kind = ('plugin-private', 'plugin-storage') if name == 'private' else ('federation-board-operations', 'attempt')
        binding = OwnerBinding(value['kernelScope']['hubId'], domain, pins['entityId'], kind,
            canonical_bytes(pins['scope']))
        source = _stream_identity(pins['streamIdentity'])
        # OwnerHistory's SQLite connection belongs to this event-loop thread.
        # Keep construction and registration together across cancellation.
        self._open()
        history = OwnerHistory(pins['history']['path'], binding,
            stream_identity=source, max_records=pins['history']['maxRecords'], max_bytes=pins['history']['maxBytes'])
        self._histories.append(history)
        checkpoint = await self._files(CheckpointHost, pins['checkpoint']['path'], stream=pins['stream'],
            commit_ref=pins['checkpoint']['commitRef'], binding=binding, stream_identity=source,
            max_records=pins['history']['maxRecords'], max_bytes=pins['history']['maxBytes'])
        backup_host = await self._files(BackupHost,
            *(backup_pins[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup_pins['destinationId'], binding=binding, stream_identity=source)
        await self._files(backup_host.load_key, backup_pins['keyId'])
        limits = pins['retention']
        ledger = OwnerLedger(jetstream, stream=pins['stream'], subject=owner_subject(binding),
            binding=binding, retention=Retention(limits['maxBytes'], limits['reserveBytes'], limits['replicas']),
            stream_identity=source, history=history, require_completion_budget=True)

        async def unavailable_artifact(_reference):
            raise ContractError('selected_storage_artifact_unavailable')

        backup = _StorageBackupLifecycle(history, binding, source, backup_host, key_id=backup_pins['keyId'],
            retrieve_artifact=unavailable_artifact, ledger=ledger)
        custody = _StorageLedgerCustody(ledger, history, checkpoint, backup)
        self._custody.append(custody)
        await custody.start()
        self._open()
        return ledger

    async def _board(self, board):
        if 'board' not in self._preconstructed_sources:
            self._audit = BoardAuditMirrorHost(board['auditMirror'], repository=board['repository'],
                local_peer=board['localPeer'], owner_uid=os.getuid(),
                migration_recovery=self._legacy_recovery)
            await self._audit.start()
        self._open()
        allocation = await self._publisher('allocation')
        card = await self._publisher('card')
        phase = board['phaseAuthority']
        seed = await self._files(self._selection.load_storage_signing_seed, 'phase')
        actors = tuple(BoardActor(item['identityRef'], item['transportRef'], item['address']) for item in board['actors'])
        scope = canonical_bytes(self._selection.policy['storage']['scope'])
        hub = self._selection.policy['kernelScope']['hubId']
        repository = board['repository']
        permit = self._startup_permits.get('board')
        domain = board['cardPublisher']['connection']['jetstreamDomain'] or ''
        source = _stream_identity(board['kvStreamIdentity'])
        target = BoardAllocationTarget(repository['repositoryId'], repository['counterPrefix'], source, domain)
        prefix_ledger = await self._ledger('allocation', allocation.jetstream)
        prefix = BoardAllocationResource(OwnerBinding(hub, 'federation-board',
            prefix_ledger._binding.entity_id, 'board-prefix', scope), self._audit.board_for(allocation),
            repository['localName'], target, _bootstrap=permit)
        prefix_journal = BoardAllocationJournal(prefix_ledger, self._authority,
            owner_service_identity_ref=phase['serviceIdentityRef'], target_binding=target)
        prefix_signer = BoardPhaseSigner(prefix_journal, self._ingress, transport_ref=phase['transportRef'],
            grants=phase['allocationGrants'], signing_seed=seed)
        prefix_owner = BoardAllocationOwner(prefix, prefix_journal, prefix_signer, actors=actors)
        self._board_owners.append(prefix_owner)
        prefix_route = allocation.bind_allocation(prefix_owner, _bootstrap=permit)
        ledger = await self._ledger('card', card.jetstream)
        resource = FederationBoardResource(OwnerBinding(hub, 'federation-board', board['resourceRef']['id'],
            'board-card', scope), self._audit.board_for(card), repository['localName'], repository['repositoryId'],
            board['cardKey'], source, _bootstrap=permit)
        journal = BoardOperationJournal(ledger, self._authority, owner_service_identity_ref=phase['serviceIdentityRef'],
            target_binding=BoardTargetBinding(repository['repositoryId'], board['cardKey'], source, domain))
        signer = BoardPhaseSigner(journal, self._ingress, transport_ref=phase['transportRef'],
            grants=phase['cardGrants'], signing_seed=seed)
        owner = BoardMutationOwner(resource, journal, signer, actors=actors)
        self._board_owners.append(owner)
        self._routes.append(card.bind(owner, allocation_route=prefix_route, _bootstrap=permit))
        # The enrolled revision is a floor. Later valid writes must survive a
        # restart with this same selection and retained operation journal.
        if permit is not None:
            await permit.validate(resource, board['resourceRef']['revision'])
        else:
            await resource._stream()
            kv = await resource._key_value()
            entry = await kv.get(repository['repositoryId'] + '.card.' + board['cardKey'])
            if type(entry.revision) is not int or entry.revision < board['resourceRef']['revision']:
                raise ContractError('selected_storage_unavailable')
            await resource.read(entry.revision)
        self._open()
        self._resources.append(resource)

    async def _messages(self, selected):
        from .messages import MessageActor, LegacyMessageActor, MessageStorageResource
        from .messages_host import MessageStoreHost, SelectedMessageDomain
        repository = selected['repository']
        source = self._preconstructed_sources.get('messages', self._audit)
        same_repository = (source is not None and repository is not None
            and all(source._repository[key] == repository[key] for key in repository))
        if 'messages' not in self._preconstructed_sources and (
                source is None or source._pins != selected['source'] or not same_repository):
            source = MessageStoreHost(selected['source'], repository=repository,
                local_peer=selected['localPeer'], owner_uid=os.getuid(), migration_recovery=self._legacy_recovery)
            self._message_stores.append(source)
            await source.start()
        elif source._peer != selected['localPeer']:
            raise ContractError('selected_storage_configuration')
        self._preconstructed_sources.setdefault('messages', source)
        permit = self._startup_permits.get('messages')
        await self._startup_db('messages', MessageStoreHost.check_message_tables, source._store)
        self._open()
        scope = self._selection.policy['storage']['scope']
        session = FederationSession()
        self._message_sessions.append(session)
        domain = SelectedMessageDomain(source, session, identity=self._identity, scope=scope,
            local_node=selected['localNode'])
        await self._startup_db('messages', source._store.configure_identity_fencing, self._authority._hub)
        from hub.fed.message_services import LocalMessages, FederationPublisher
        for channel in selected['channels']:
            resource = MessageStorageResource(OwnerBinding(self._authority._hub, 'federation-messages',
                channel['resourceRef']['id'], 'message-channel', canonical_bytes(scope)),
                LocalMessages(domain), FederationPublisher(domain),
                repository=None if repository is None else repository['localName'], peer=channel['peer'],
                actors=tuple(MessageActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                    actor['caller']) for actor in channel['actors']),
                legacy_actors=tuple(LegacyMessageActor(canonical_bytes(actor['identityRef']),
                    canonical_bytes(actor['transportRef']), actor['caller'], canonical_bytes(actor['grants']))
                    for actor in channel.get('legacyActors', ())),
                plugin_identity_ref=channel['pluginIdentityRef'], instance_id=channel['instanceId'],
                initial_source=channel['initialSource'], _bootstrap=permit)
            current = await self._startup_db('messages', resource._journal.current)
            if current['revision'] < channel['resourceRef']['revision']:
                raise ContractError('selected_storage_unavailable')
            if permit is not None:
                await permit.validate(resource, current['revision'])
            else:
                await resource.read(current['revision'])
            self._resources.append(resource)
            self._open()

    async def _knowledge(self, selected):
        from .knowledge import KnowledgeStorageResource
        from .knowledge_host import KnowledgeStoreHost, SelectedKnowledgeDomain
        from .messages import MessageActor, MessageStorageResource
        from .knowledge_legacy import LegacyKnowledgeActor
        from .work import WorkStorageResource
        repository = selected['repository']
        source = self._preconstructed_sources.get('knowledge') or next((candidate for candidate in (self._audit, *self._message_stores)
            if candidate is not None and candidate._pins == selected['source']
            and candidate._peer == selected['localPeer']
            and candidate._repository is not None
            and all(candidate._repository[key] == repository[key] for key in repository)), None)
        if source is None:
            source = KnowledgeStoreHost(selected['source'], repository=repository,
                local_peer=selected['localPeer'], owner_uid=os.getuid(), migration_recovery=self._legacy_recovery)
            self._message_stores.append(source)
            await source.start()
        self._preconstructed_sources.setdefault('knowledge', source)
        permit = self._startup_permits.get('knowledge')
        await self._startup_db('knowledge', KnowledgeStoreHost.check_knowledge_tables, source._store)
        self._open()
        scope = self._selection.policy['storage']['scope']
        session = FederationSession()
        self._message_sessions.append(session)
        domain = SelectedKnowledgeDomain(source, session, identity=self._identity, scope=scope,
            local_node=selected['localNode'])
        for channel in selected['channels']:
            message_sources = []
            for reference in channel.get('messageSources', ()):
                matches = [resource for resource in self._resources
                    if type(resource) is MessageStorageResource
                    and resource.binding.entity_id == reference['id']
                    and resource.binding.hub_id == reference['ownerHubId']]
                if len(matches) != 1:
                    raise ContractError('selected_storage_configuration')
                message = matches[0]
                current = await self._startup_db('messages', message._journal.current)
                if current['revision'] < reference['revision']:
                    raise ContractError('selected_storage_unavailable')
                message_sources.append(message)
            work_sources = []
            for reference in channel.get('workSources', ()):
                matches = [resource for resource in self._resources
                    if type(resource) is WorkStorageResource
                    and resource.binding.entity_id == reference['id']
                    and resource.binding.hub_id == reference['ownerHubId']
                    and resource.binding.scope == canonical_bytes(scope)
                    and resource.repository == repository['localName']
                    and resource._store is source._store
                    and resource._source is source]
                if len(matches) != 1:
                    raise ContractError('selected_storage_configuration')
                work = matches[0]
                current = await self._startup_db('work', work._journal.current)
                if current['revision'] < reference['revision']:
                    raise ContractError('selected_storage_unavailable')
                work_sources.append(work)
            resource = KnowledgeStorageResource(OwnerBinding(self._authority._hub, 'federation-knowledge',
                channel['resourceRef']['id'], 'knowledge-channel', canonical_bytes(scope)), domain,
                repository=repository['localName'],
                actors=tuple(MessageActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                    actor['caller']) for actor in channel['actors']),
                legacy_actors=tuple(LegacyKnowledgeActor(canonical_bytes(actor['identityRef']),
                    canonical_bytes(actor['transportRef']), actor['caller'], canonical_bytes(actor['grants']))
                    for actor in channel.get('legacyActors', ())),
                message_sources=tuple(message_sources),
                work_sources=tuple(work_sources),
                plugin_identity_ref=channel['pluginIdentityRef'], instance_id=channel['instanceId'],
                initial_source=channel['initialSource'], _bootstrap=permit)
            current = await self._startup_db('knowledge', resource._journal.current)
            if current['revision'] < channel['resourceRef']['revision']:
                raise ContractError('selected_storage_unavailable')
            if permit is not None:
                await permit.validate(resource, current['revision'])
            else:
                await resource.read(current['revision'])
            self._resources.append(resource)
            self._open()

    async def _code(self, selected):
        from .code import CodeStorageResource
        from .code_host import CodeStoreHost, SelectedCodeDomain
        from .messages import MessageActor, MessageStorageResource
        from .code_legacy import LegacyCodeActor
        repository = selected['repository']
        source = self._preconstructed_sources.get('code') or next((candidate for candidate in (self._audit, *self._message_stores)
            if candidate is not None and candidate._pins == selected['source']
            and candidate._peer == selected['localPeer']
            and candidate._repository is not None
            and all(candidate._repository[key] == repository[key] for key in repository)), None)
        if source is None:
            source = CodeStoreHost(selected['source'], repository=repository,
                local_peer=selected['localPeer'], owner_uid=os.getuid(), migration_recovery=self._legacy_recovery)
            self._message_stores.append(source)
            await source.start()
        self._preconstructed_sources.setdefault('code', source)
        permit = self._startup_permits.get('code')
        await self._startup_db('code', CodeStoreHost.check_code_tables, source._store)
        self._open()
        scope = self._selection.policy['storage']['scope']
        session = FederationSession()
        self._message_sessions.append(session)
        domain = SelectedCodeDomain(source, session, identity=self._identity, scope=scope,
            local_node=selected['localNode'])
        for channel in selected['channels']:
            resource = CodeStorageResource(OwnerBinding(self._authority._hub, 'federation-code',
                channel['resourceRef']['id'], 'code-channel', canonical_bytes(scope)), domain,
                repository=repository['localName'],
                actors=tuple(MessageActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                    actor['caller']) for actor in channel['actors']),
                legacy_actors=tuple(LegacyCodeActor(canonical_bytes(actor['identityRef']),
                    canonical_bytes(actor['transportRef']), actor['caller'], canonical_bytes(actor['grants']))
                    for actor in channel.get('legacyActors', ())),
                plugin_identity_ref=channel['pluginIdentityRef'], instance_id=channel['instanceId'],
                initial_source=channel['initialSource'], _bootstrap=permit)
            current = await self._startup_db('code', resource._journal.current)
            if current['revision'] < channel['resourceRef']['revision']:
                raise ContractError('selected_storage_unavailable')
            if permit is not None:
                await permit.validate(resource, current['revision'])
            else:
                await resource.read(current['revision'])
            self._resources.append(resource)
            self._open()

    async def _work(self, selected):
        from .work import WorkStorageResource
        from .work_host import WorkStoreHost, SelectedWorkDomain
        from .messages import MessageActor
        from .messages_host import MessageStoreHost
        from .knowledge_host import KnowledgeStoreHost
        from .code_host import CodeStoreHost
        from .work_legacy import LegacyWorkActor
        repository = selected['repository']
        source = self._preconstructed_sources.get('work') or next((candidate
            for candidate in (self._audit, *self._message_stores)
            if type(candidate) in (WorkStoreHost, BoardAuditMirrorHost, MessageStoreHost,
                KnowledgeStoreHost, CodeStoreHost)
            and candidate._pins == selected['source'] and candidate._peer == selected['localPeer']
            and (candidate._repository == repository or repository is not None
                and candidate._repository is not None
                and all(candidate._repository.get(key) == value for key, value in repository.items()))), None)
        if source is None:
            # A different declaration must not open a second owner of the same file.
            if any(candidate is not None
                    and candidate._pins['database']['path'] == selected['source']['database']['path']
                    for candidate in (self._audit, *self._message_stores)):
                raise ContractError('selected_storage_configuration')
            source = WorkStoreHost(selected['source'], repository=repository,
                local_peer=selected['localPeer'], owner_uid=os.getuid(),
                migration_recovery=self._legacy_recovery)
            self._message_stores.append(source)
            await source.start()
        self._preconstructed_sources.setdefault('work', source)
        permit = self._startup_permits.get('work')
        await self._startup_db('work', WorkStoreHost.check_work_tables, source._store)
        await self._startup_db('work', source._store.configure_identity_fencing, self._authority._hub)
        self._open()
        scope = self._selection.policy['storage']['scope']
        session = None
        if 'policy' in selected['source']:
            session = FederationSession()
            self._message_sessions.append(session)
        resources = []
        for channel in selected['channels']:
            _, _, channel_repository, channel_scope = self._selection.work_channel_projection(channel['resourceRef'])
            domain = SelectedWorkDomain(source, session, identity=self._identity, scope=channel_scope,
                local_node=selected['localNode'], selection=self._selection, channel_ref=channel['resourceRef'], _bootstrap=permit)
            self._work_domains.append(domain)
            resource = WorkStorageResource(OwnerBinding(self._authority._hub, 'federation-work',
                channel['resourceRef']['id'], 'work-channel', canonical_bytes(channel_scope)), domain,
                repository=None if channel_repository is None else channel_repository['localName'],
                actors=tuple(MessageActor(canonical_bytes(actor['identityRef']),
                    canonical_bytes(actor['transportRef']), actor['caller']) for actor in channel['actors']),
                legacy_actors=tuple(LegacyWorkActor(canonical_bytes(actor['identityRef']),
                    canonical_bytes(actor['transportRef']), actor['caller'], canonical_bytes(actor['grants']))
                    for actor in channel.get('legacyActors', ())),
                legacy_authority=self._authority, plugin_identity_ref=channel['pluginIdentityRef'],
                instance_id=channel['instanceId'], initial_source=channel['initialSource'], _bootstrap=permit,
                first_worker=channel.get('firstWorker'))
            current = await self._startup_db('work', resource._journal.current)
            if current['revision'] < channel['resourceRef']['revision']:
                raise ContractError('selected_storage_unavailable')
            if permit is not None:
                await permit.validate(resource, current['revision'])
            else:
                await resource.read(current['revision'])
            self._resources.append(resource)
            resources.append(resource)
            self._open()
        from .work_lifecycle import LIFECYCLE_COMMANDS, WorkLifecycleOwner
        lifecycle = tuple(resource for resource in resources if resource.repository is not None
            and any(set(strict_loads(actor.grants)) & LIFECYCLE_COMMANDS for actor in resource._legacy_actors))
        if lifecycle:
            self._work_lifecycle_owners.append(WorkLifecycleOwner(lifecycle))
            self._open()

    async def _peer_control(self):
        from identity.peer_control import control_storage
        from .peer_control_command import PeerControlCommandOwner
        from hub.fed.peer_control import PeerControlPublisher
        declared = self._selection.policy.get('peerControl', {}).get('routes', ())
        sources = []
        for route in declared:
            if not route.get('operators'):
                continue
            if 'publisher' not in route:
                raise ContractError('selected_storage_configuration')
            domain, _ = control_storage(self._selection.policy, route)
            matches = [item for item in self._resources
                if item.domain == domain
                and item.binding.entity_id == route['resourceRef']['id']
                and item.binding.hub_id == route['resourceRef']['ownerHubId']
                and strict_loads(item.binding.scope) == route['scope']]
            resource = matches[0] if len(matches) == 1 else None
            source = None if resource is None else getattr(resource._owner, '_source', None)
            if source is None:
                raise ContractError('selected_storage_configuration')
            if not any(source is existing for existing in sources):
                sources.append(source)
            publisher = PeerControlPublisher(self._selection, self._identity, route_id=route['routeId'])
            self._peer_control_publishers.append(publisher)
            await publisher.start()
            self._open()
        if self._peer_control_publishers:
            if len(sources) != 1:
                raise ContractError('selected_storage_configuration')
            self._peer_control_owners.append(PeerControlCommandOwner(self._selection, self._identity,
                sources[0], tuple(self._peer_control_publishers)))

    async def _start_resources(self):
        self._open()
        await self._selection.check_storage_authority(self._identity)
        self._open()
        selected = self._selection.policy['storage']
        await self._prepare_policy_sources()
        if 'privateStorage' in selected:
            pin = selected['privateStorage']
            client = await self._connect('private')
            domain = pin['publisher']['connection']['jetstreamDomain']
            jetstream = client.jetstream() if domain is None else client.jetstream(domain=domain)
            ledger = await self._ledger('private', jetstream)
            resource = PrivateStorageResource(ledger._binding, ledger, canonical_bytes(pin['pluginIdentityRef']),
                pin['instanceId'], pin['packageId'], domain or '')
            if resource.binding_digest != pin['bindingDigest']:
                raise ContractError('selected_storage_unavailable')
            # A selected private namespace is existing data, never seeded here.
            snapshot = await ledger.current()
            if snapshot.latest is None:
                raise ContractError('selected_storage_unavailable')
            resource.document(snapshot.latest.record)
            self._open()
            self._resources.append(resource)
        if 'board' in selected:
            await self._board(selected['board'])
        if 'messages' in selected:
            await self._messages(selected['messages'])
        if 'work' in selected:
            await self._work(selected['work'])
        if 'knowledge' in selected:
            await self._knowledge(selected['knowledge'])
        if 'code' in selected:
            await self._code(selected['code'])
        await self._peer_control()
        if self._selection.policy.get('peerControl', {}).get('routes'):
            from identity.peer_control import control_storage
            domains = {control_storage(self._selection.policy, pin)[0]
                for pin in self._selection.policy['peerControl']['routes']}
            if 'knowledge' in domains:
                from .knowledge import KnowledgeStorageResource
                from .knowledge_control import KnowledgeControlOwner
                control = KnowledgeControlOwner(self._selection, self._identity,
                    tuple(resource for resource in self._resources if type(resource) is KnowledgeStorageResource))
                self._knowledge_controls.append(control)
                await control.start(_bootstrap=self._startup_permits.get('knowledge'))
                self._open()
            if 'work' in domains:
                from .work import WorkStorageResource
                from .work_control import WorkControlOwner
                control = WorkControlOwner(self._selection, self._identity,
                    tuple(resource for resource in self._resources if type(resource) is WorkStorageResource))
                self._work_controls.append(control)
                await control.start(_bootstrap=self._startup_permits.get('work'))
                self._open()
        if self._selection.policy.get('coreWorkTransport', {}).get('routes'):
            from .core_work import CoreWorkOwner
            from .work import WorkStorageResource
            self._core_work_owners.append(CoreWorkOwner(self._selection, self._identity,
                tuple(resource for resource in self._resources if type(resource) is WorkStorageResource)))
        groups = {}
        for resource in self._resources:
            groups.setdefault(resource.binding.scope, []).append(resource)
        self._receiver_scopes = tuple(sorted(groups))
        for name in ('storage', 'outcome'):
            connection = await self._connect(name)
            seed = await self._files(self._selection.load_storage_signing_seed, name)
            pin = self._selection.storage_descriptor(name)
            value = self._selection.policy
            for scope in self._receiver_scopes:
                resources = tuple(groups[scope])
                message_bridge = knowledge_bridge = code_bridge = work_bridge = peer_control = None
                if name == 'storage':
                    from .message_bridge_service import MessageBridgeService
                    from .messages import MessageStorageResource
                    messages = tuple(r for r in resources
                        if type(r) is MessageStorageResource and r._legacy_actors)
                    if messages:
                        message_bridge = MessageBridgeService(self._ingress, resources=messages,
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed)
                    from .knowledge_bridge_service import KnowledgeBridgeService
                    from .knowledge import KnowledgeStorageResource
                    knowledge = tuple(r for r in resources
                        if type(r) is KnowledgeStorageResource and r._legacy_actors)
                    if knowledge:
                        knowledge_bridge = KnowledgeBridgeService(self._ingress, resources=knowledge,
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed)
                    from .code_bridge_service import CodeBridgeService
                    from .code import CodeStorageResource
                    code = tuple(r for r in resources
                        if type(r) is CodeStorageResource and r._legacy_actors)
                    if code:
                        code_bridge = CodeBridgeService(self._ingress, resources=code,
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed)
                    from .work_bridge_service import WorkBridgeService
                    from .work import WorkStorageResource
                    work = tuple(r for r in resources if type(r) is WorkStorageResource and r._legacy_actors)
                    if work:
                        work_bridge = WorkBridgeService(self._ingress, resources=work,
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed)
                    if self._peer_control_owners and scope == canonical_bytes(value['storage']['scope']):
                        from .peer_control_service import PeerControlCommandService
                        peer_control = PeerControlCommandService(self._ingress, self._peer_control_owners[0],
                            service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                            signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed)
                service = CapabilityReplyService(self._authority, resources=resources,
                    hub_id=value['kernelScope']['hubId'], profile_id=value['kernelScope']['profileId'],
                    authority_id=value['authorityId'], service_id=name + '-owner',
                    service_identity_ref=pin['serviceIdentityRef'], service_instance_id=pin['serviceInstanceId'],
                    signing_key_ref=pin['issuer']['issuerRef'], signing_seed=seed,
                    request_signing_key_ref=pin['requestSigningKeyRef'], connection=connection,
                    board_routes=self._routes if scope == canonical_bytes(value['storage']['scope']) else (), message_bridge=message_bridge, knowledge_bridge=knowledge_bridge,
                    peer_control=peer_control, code_bridge=code_bridge, work_bridge=work_bridge)
                self._receivers.append(service)
                await service.start()
                self._open()
        await self._selection.check_storage_authority(self._identity)
        self._open()
        for owner in self._core_work_owners:
            await owner.start(_bootstrap=self._startup_permits.get('work'), _watch_roles=True)
            self._open()
    async def _start(self):
        try:
            await self._start_resources()
        finally:
            for permit in tuple(self._startup_permits.values()):
                await permit.close()
            self._startup_permits.clear()
        self._open()
        self._ready = True
        self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:
            raise ContractError('selected_storage_unavailable')
        self._starting = asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            await asyncio.shield(self._starting)
        except asyncio.CancelledError:
            self.fence()
            raise
        except Exception as error:
            self.fence()
            raise SelectedStorageFailure('selected_storage_start_unconfirmed', self, error) from None

    def check_health(self):
        try:
            self._open()
            if not self._ready or len(self._receivers) != 2 * len(getattr(self, '_receiver_scopes', (None,))):
                raise ValueError()
            for publisher in self._publishers:
                publisher.check()
            for client in self._clients:
                if client.is_connected is not True:
                    raise ValueError()
            for service in self._receivers:
                if service._closed or service._subscription is None:
                    raise ValueError()
            for custody in self._custody:
                custody.check()
            for publisher in self._peer_control_publishers:
                publisher.check()
            for owner in self._peer_control_owners:
                owner.check()
            for control in self._knowledge_controls:
                control.check_health()
            for control in self._work_controls:
                control.check_health()
            for owner in getattr(self, '_core_work_owners', ()):
                owner.check_health()
            for owner in getattr(self, '_work_lifecycle_owners', ()):
                owner._current()
            for source in self._message_stores:
                source.check_health()
            if self._audit is not None:
                self._audit.check_health()
        except Exception as error:
            self.fence()
            raise SelectedStorageFailure('selected_storage_unavailable', self, error) from None

    def fence(self):
        self._closed, self._ready = True, False
        for service in self._receivers:
            service._closed = True

    async def _cleanup(self):
        if self._starting is not None:
            if not self._starting.done():
                self._starting.cancel()
            await asyncio.gather(self._starting, return_exceptions=True)
        # A request waiter or admission join is not the original transition.
        # Its commit, reads and filesystem projection must finish before their
        # borrowed sources, writers or keys can be released.
        for transition in tuple(self._policy_transitions):
            await transition.close()
        if self._policy_change is not None:
            await _join_terminal(self._policy_change[2])
        for service in reversed(self._receivers):
            await service.close()
        for owner in reversed(self._peer_control_owners):
            await owner.close(timeout=None)
        for control in reversed(getattr(self, '_knowledge_controls', ())):
            await control.close(timeout=None)
        for control in reversed(getattr(self, '_work_controls', ())):
            await control.close(timeout=None)
        for owner in reversed(getattr(self, '_core_work_owners', ())):
            await owner.close(timeout=None)
        for owner in reversed(getattr(self, '_work_lifecycle_owners', ())):
            await owner.close()
        for domain in reversed(getattr(self, '_work_domains', ())):
            await domain.close()
        for publisher in reversed(self._peer_control_publishers):
            await publisher.close(timeout=None)
        for owner in reversed(self._board_owners):
            await owner.close(timeout=None)
        # Card joins while its allocation gate and original publisher are live.
        for publisher in reversed(self._publishers):
            await publisher.close()
        for custody in reversed(self._custody):
            await custody.close()
        for session in self._message_sessions:
            await session.close()
        for source in reversed(self._message_stores):
            await source.close()
        if self._audit is not None:
            await self._audit.close()
        for original in self._connects:
            await asyncio.gather(original, return_exceptions=True)
        for session in reversed(self._sessions):
            await session.close()
        for client in reversed(self._clients):
            await client.close()
        if self._workers:
            await asyncio.gather(*tuple(self._workers), return_exceptions=True)
        for history in self._histories:
            history.close()

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('selected_storage_cleanup_invalid')
        if asyncio.get_running_loop() is not self._loop:
            raise SelectedStorageFailure('selected_storage_owner_loop', self)
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
            raise SelectedStorageFailure('selected_storage_cleanup_incomplete', self, error) from None
