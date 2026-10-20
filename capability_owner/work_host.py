"""Checked custody of existing work records, including unshared local work."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import re
import threading

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.store import MIGRATIONS, Store, _split_sql
from identity.service import IdentityService
from .messages_host import MessageStoreHost
from .selected_storage import BoardAuditMirrorHost, _file_identity


def _normalized_sql(sql):
    # Preserve quoted values; changing an event name changes product behavior.
    tokens = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", sql)
    return ''.join(token if token.startswith(("'", '\"')) else ''.join(token.lower().split())
        for token in tokens)


class WorkStoreHost(MessageStoreHost):
    """Open the selected Store without migrations or a federation requirement."""
    def __init__(self, pins, *, repository, local_peer=None, owner_uid,
                 migration_recovery=None):
        local = type(pins) is dict and set(pins) == {'database'}
        if not local:
            if repository is not None and not MessageStoreHost._repository_descriptor(repository):
                raise ContractError('selected_work_store_invalid')
            super().__init__(pins, repository=repository, local_peer=local_peer,
                owner_uid=owner_uid, migration_recovery=migration_recovery)
            self._local = False
            return
        if (type(pins['database']) is not dict
                or set(pins['database']) != {'path', 'applicationId', 'userVersion'}
                or repository is not None and (type(repository) is not dict
                    or set(repository) != {'localName'} or type(repository['localName']) is not str
                    or re.fullmatch(r'[a-z0-9_]{1,32}', repository['localName']) is None)
                or local_peer is not None or type(owner_uid) is not int or owner_uid != os.getuid()):
            raise ContractError('selected_work_store_invalid')
        self._pins = strict_loads(canonical_bytes(pins))
        self._repository = strict_loads(canonical_bytes(repository))
        self._local, self._peer, self._uid = True, None, owner_uid
        self._migration_recovery = migration_recovery
        self._loop = asyncio.get_running_loop()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='selected-work-db')
        self._store = self._policy = self._database_identity = self._policy_identity = None
        self._failed_custody = None
        self._pending, self._worker = set(), threading.local()
        self._starting = self._closing = None
        self._closed = False
        self._policy_transition = None
        self._policy_paused = self._policy_replacing = self._policy_suspended = False
        self._policy_generation = 0
        self._opening_policy = None
        self._resource_bootstraps, self._resource_bootstrap_calls = set(), set()

    def __repr__(self):
        return '<WorkStoreHost private>'

    @staticmethod
    def _tables():
        return (
            ('work_items', {'id', 'parent_id', 'task_key', 'repo', 'target', 'title', 'body',
                'created_by', 'requirements', 'priority', 'state', 'claimed_by', 'lease_until',
                'attempts', 'max_attempts', 'result', 'blocked_reason', 'created', 'updated',
                'origin', 'origin_peer', 'fed_flags'}),
            ('claims', {'repo', 'path', 'holder', 'work_id', 'lease_until', 'created'}),
            ('agents', {'session', 'repo', 'role', 'agent', 'cli', 'role_snapshot',
                'transport', 'handle', 'pane_pid', 'token_sha', 'state', 'state_note',
                'last_seen', 'last_output', 'last_bell', 'created', 'term_name', 'generation'}),
            ('repos', {'repo', 'title', 'created'}),
            ('groups', {'grp', 'repo'}),
            ('teams', {'repo', 'team', 'lead_role', 'created'}),
            ('team_members', {'repo', 'team', 'session'}),
            ('legacy_names', {'legacy', 'session'}),
            ('deliveries', {'message_id', 'recipient', 'state', 'attempts', 'next_at',
                'last_error', 'evidence', 'updated'}),
            ('events', {'seq', 'at', 'entity', 'entity_id', 'event', 'actor', 'detail'}),
            ('nats_outbox', {'seq', 'subject', 'payload', 'created', 'sent'}),
            ('fed_seen', {'msg_id', 'at'}),
            *MessageStoreHost._tables()[2:])

    @staticmethod
    def check_work_tables(store):
        if type(store) is not Store:
            raise ContractError('selected_work_store_invalid')
        for table, columns in WorkStoreHost._tables():
            actual = {row['name'] for row in store.q('PRAGMA table_info(' + table + ')')}
            if not columns <= actual:
                raise ContractError('selected_work_store_invalid')
        # Compare against the retained Store definitions so omitted provenance or
        # terminal-result triggers cannot make an incomplete source ready.
        required = {'work_audit', 'work_audit_ins', 'agents_audit', 'deliveries_audit', 'fed_work_terminal'}
        for migration in MIGRATIONS:
            for statement in _split_sql(migration):
                match = re.match(r'\s*CREATE\s+TRIGGER\s+(\w+)', statement, re.I)
                if match is not None and match[1] in required:
                    row = store.q1('SELECT sql FROM sqlite_master WHERE type=? AND name=?',
                        ('trigger', match[1]))
                    if row is None or _normalized_sql(row['sql']) != _normalized_sql(statement.rstrip(';')):
                        raise ContractError('selected_work_store_invalid')
                    required.remove(match[1])
        if required:
            raise ContractError('selected_work_store_invalid')
        # table_info omits generated columns. Work routing requires this exact
        # generated expression, rather than a writable lookalike column.
        columns = {row['name']: row for row in store.q('PRAGMA table_xinfo(work_items)')}
        sql = store.q1("SELECT sql FROM sqlite_master WHERE type='table' AND name='work_items'")
        generated = 'target_kindtextgeneratedalwaysas(substr(target,1,instr(target,\':\')-1))virtual'
        if (columns.get('target_kind', {}).get('hidden') != 2
                or sql is None or generated not in _normalized_sql(sql['sql'])):
            raise ContractError('selected_work_store_invalid')

    def _open_existing(self):
        if not self._local:
            super()._open_existing()
        else:
            try:
                selected = self._pins['database']
                self._store = Store.open_existing(selected['path'], application_id=selected['applicationId'],
                    user_version=selected['userVersion'], owner_uid=self._uid,
                    migration_recovery=self._migration_recovery)
                self._database_identity = _file_identity(selected['path'], mutable=True)
            except BaseException as error:
                if getattr(error, 'owner', None) is not None:
                    self._failed_custody = error.owner
                raise
        self.check_work_tables(self._store)
        if (self._repository is not None and self._store.q1('SELECT repo FROM repos WHERE repo=?',
                (self._repository['localName'],)) is None):
            raise ContractError('selected_work_store_invalid')
        self._schema_version = self._store.q1('PRAGMA schema_version')['schema_version']

    def _check_files(self):
        if not self._local:
            super()._check_files()
        elif (self._store is None
                or self._database_identity != _file_identity(self._pins['database']['path'], mutable=True)):
            raise ContractError('selected_work_store_unavailable')
        if getattr(self._worker, 'active', False):
            self._check_schema()

    def _check_schema(self):
        selected = self._pins['database']
        if (self._store.q1('PRAGMA schema_version')['schema_version'] != self._schema_version
                or self._store.q1('PRAGMA application_id')['application_id'] != selected['applicationId']
                or self._store.q1('PRAGMA user_version')['user_version'] != selected['userVersion']):
            raise ContractError('selected_work_store_unavailable')

    async def db(self, function, *args, **kwargs):
        def checked():
            self._check_files()
            return function(*args, **kwargs)
        return await super().db(checked)


class _SelectedWorkAttribution:
    """Retain local attribution separately from the federation wire address."""
    def __init__(self, domain):
        self._domain, self.dbx = domain, domain._executor

    def sender_of(self, caller):
        self._domain._current()
        from hub.server import Hub
        return Hub.sender_of(self, caller)


class SelectedWorkDomain:
    """Borrow one admitted source; its owner retains the connection and executor."""
    def __init__(self, source, session=None, *, identity, scope, local_node, selection=None, channel_ref=None, _bootstrap=None):
        from .code_host import CodeStoreHost
        from .knowledge_host import KnowledgeStoreHost
        from identity.application_service_selection import ApplicationServiceSelection
        if type(source) not in (WorkStoreHost, BoardAuditMirrorHost, MessageStoreHost, KnowledgeStoreHost, CodeStoreHost):
            raise ContractError('selected_work_domain_invalid')
        from .policy_bootstrap import PolicyResourceBootstrap
        if _bootstrap is not None and type(_bootstrap) is not PolicyResourceBootstrap:
            raise ContractError('selected_work_domain_invalid')
        self._bootstrap = _bootstrap
        self._selection = self._bound_selection = selection
        self._selection_document = None
        self._channel_ref = None
        repository = source._repository
        if selection is not None or channel_ref is not None:
            if type(selection) is not ApplicationServiceSelection or type(channel_ref) is not dict:
                raise ContractError('selected_work_domain_invalid')
            selected, channel, repository, selected_scope = selection.work_channel_projection(channel_ref)
            if (selected['source'] != source._pins or selected['localPeer'] != source._peer
                    or (selected['repository'] is None) != (source._repository is None)
                    or selected['repository'] is not None and any(
                        source._repository.get(key) != value for key, value in selected['repository'].items())
                    or selected['localNode'] != local_node
                    or selected_scope != scope):
                raise ContractError('selected_work_domain_invalid')
            self._selection_document = selection.document
            self._channel_ref = canonical_bytes(channel_ref)
        self._bound_repository = canonical_bytes(repository)
        if (type(source) not in (WorkStoreHost, BoardAuditMirrorHost, MessageStoreHost,
                    KnowledgeStoreHost, CodeStoreHost)
                or type(identity) is not IdentityService
                or type(scope) is not dict or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or scope['organizationId'] != identity.reader._organization
                or (scope['projectId'] is None) != (repository is None)
                or type(local_node) is not str or re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', local_node) is None
                or session is not None and type(session) is not FederationSession
                or (session is None) != (source._policy is None)):
            raise ContractError('selected_work_domain_invalid')
        source.check_health()
        self._source, self.session = source, session
        self._store, self._connection, self._executor = source._store, source._store.db, source._executor
        self._identity, self._identity_reader = identity, identity.reader
        self._identity_pins = (identity.reader._hub, identity.reader._entity,
            identity.reader._profile, identity.reader._organization)
        self._scope, self.node = canonical_bytes(scope), local_node
        self._bound_scope, self._node = self._scope, local_node
        self._source_pins = canonical_bytes(source._pins)
        self._repository = canonical_bytes(source._repository)
        self._policy, self._session, self.me = source._policy, session, source._peer
        self._policy_generation = source._policy_generation
        WorkStoreHost.check_work_tables(self._store)
        self._schema_version = self._store.q1('PRAGMA schema_version')['schema_version']
        self._closed, self._pending = False, set()
        self.hub = _SelectedWorkAttribution(self)
        self._current()

    def __repr__(self):
        return '<SelectedWorkDomain private>'

    def _current(self):
        if (self._closed or self.node != self._node or self._scope != self._bound_scope
                or canonical_bytes(self._source._pins) != self._source_pins
                or self._identity.reader is not self._identity_reader or self._identity._closed
                or self._identity_pins != (self._identity_reader._hub, self._identity_reader._entity,
                    self._identity_reader._profile, self._identity_reader._organization)
                or self._source._store is not self._store or self._store.db is not self._connection
                or self._source._executor is not self._executor
                or canonical_bytes(self._source._repository) != self._repository
                or self._source._policy is not self._policy or self.session is not self._session
                or self.me != self._source._peer):
            raise ContractError('capability_resource_stale')
        if getattr(self._source._worker, 'active', False):
            self._source._check_files()
            selected = self._source._pins['database']
            if (self._source._closed or self._store.q1('PRAGMA schema_version')['schema_version']
                    != self._schema_version
                    or self._store.q1('PRAGMA application_id')['application_id'] != selected['applicationId']
                    or self._store.q1('PRAGMA user_version')['user_version'] != selected['userVersion']):
                raise ContractError('capability_resource_stale')
        else:
            self._source.check_health()
            self._identity.check_health()
        if self._selection is not None:
            if (self._selection is not self._bound_selection
                    or self._selection.document != self._selection_document):
                raise ContractError('capability_resource_stale')
            selected, _, repository, scope = self._selection.work_channel_projection(strict_loads(self._channel_ref))
            if (canonical_bytes(repository) != self._bound_repository or canonical_bytes(scope) != self._scope
                    or selected['source'] != self._source._pins or selected['localPeer'] != self.me
                    or (selected['repository'] is None) != (self._source._repository is None)
                    or selected['repository'] is not None and any(self._source._repository.get(key) != value
                        for key, value in selected['repository'].items())
                    or selected['localNode'] != self.node):
                raise ContractError('capability_resource_stale')
        else:
            repository = strict_loads(self._bound_repository)
        if repository is not None:
            name = repository['localName']
            if self._store.q1('SELECT repo FROM repos WHERE repo=?', (name,)) is None:
                raise ContractError('capability_resource_stale')
            structural = False
            if self._bootstrap is not None and self._selection is not None:
                try:
                    state = self._bootstrap._state()
                    structural = (state[0] is self._source and state[1]._selection is self._selection
                        and state[4] == 'work')
                except ContractError:
                    pass
            if self._selection is not None and not structural:
                if self._policy is None:
                    if set(repository) != {'localName'}:
                        raise ContractError('capability_resource_stale')
                elif set(repository) == {'localName'}:
                    if self._policy.rid_of(name) is not None:
                        raise ContractError('capability_resource_stale')
                elif (self._policy.rid_of(name) != repository['repositoryId']
                        or self._policy.local_of(repository['repositoryId']) != name):
                    raise ContractError('capability_resource_stale')
        if self._session is not None:
            self._session.check_open()

    @property
    def store(self):
        self._current()
        return self._store

    @property
    def policy(self):
        self._current()
        if self._policy is None:
            raise ContractError('capability_access_refused')
        return self._policy

    @property
    def fcfg(self):
        return self.policy.cfg['federation']

    async def db(self, function, *args, **kwargs):
        self._current()
        def checked():
            self._current()
            return function(*args, **kwargs)
        original = asyncio.create_task(self._source.db(checked))
        self._pending.add(original)
        try:
            await asyncio.wait({original})
            return original.result()
        except asyncio.CancelledError:
            while not original.done():
                try:
                    await asyncio.wait({original})
                except asyncio.CancelledError:
                    continue
            if not original.cancelled():
                original.exception()
            raise
        finally:
            self._pending.discard(original)

    def sender_of(self, caller):
        self._current()
        from hub.server import Hub
        return Hub.sender_of(self, caller) if self._session is None else Federation.sender_of(self, caller)

    address_of = Federation.address_of
    stage = Federation.stage
    publish = Federation.publish

    def kick(self):
        self._current()

    def _resume_policy(self, transition):
        """Follow only the joined projection owned by this selected host."""
        from .federation_policy_transition import FederationPolicyTransition
        source = self._source
        host = getattr(transition, '_selected_host', None)
        if (type(transition) is not FederationPolicyTransition or host is None
                or self not in host._work_domains or host._identity is not self._identity
                or source._policy_transition is not transition or source not in transition._sources
                or source._policy_paused or source._policy_replacing
                or source._policy_generation < self._policy_generation
                or source._policy is not self._policy
                    and source._policy_generation == self._policy_generation):
            raise ContractError('capability_resource_stale')
        source.check_health()
        self._policy, self._policy_generation = source._policy, source._policy_generation
        self._current()

    async def close(self):
        self._closed = True
        while self._pending:
            await asyncio.wait(tuple(self._pending))
