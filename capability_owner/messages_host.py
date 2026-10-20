"""Selected custody for the existing message Store and its federation policy."""
from agentmux_contracts import ContractError, canonical_bytes
from hub.fed.policy import normalize_remote
from hub.fed.runtime import Federation
from hub.store import NoRecipients
from identity.legacy_identity import LegacyIdentityAdapter
from .selected_storage import BoardAuditMirrorHost


class MessageStoreHost(BoardAuditMirrorHost):
    """Reuse held Store/file/executor custody without board-specific tables."""
    @staticmethod
    def _repository_descriptor(repository):
        return repository is None or (type(repository) is dict
            and set(repository) == {'localName', 'repositoryId', 'normalizedRemote'})

    @staticmethod
    def _tables():
        return (('messages', {'id', 'sender', 'target', 'kind', 'ref', 'work_id', 'body',
                    'body_ref', 'body_sha', 'idem_key', 'created', 'expires', 'meta'}),
            ('deliveries', {'message_id', 'recipient', 'state', 'updated'}),
            ('fed_outbox', {'seq', 'msg_id', 'subject', 'payload', 'created', 'sent', 'attempts', 'last_error'}),
            ('fed_audit', {'seq', 'at', 'dir', 'plane', 'peer', 'rid', 'subject', 'msg_id', 'sha', 'size', 'decision', 'detail'}),
            ('fed_state', {'k', 'v'}),
            ('fed_quarantine', {'id', 'peer', 'plane', 'state', 'subject', 'envelope'}))

    @staticmethod
    def check_message_tables(store):
        # A shared board source has already passed board admission. Message
        # admission must also check its own tables before reporting readiness.
        for table, columns in MessageStoreHost._tables():
            present = {row['name'] for row in store.q('PRAGMA table_info(' + table + ')')}
            if not columns <= present:
                raise ContractError('selected_message_store_invalid')

    def _remotes(self, store):
        return {} if self._repository is None else super()._remotes(store)

    def _admit_policy(self, store, config, policy, remotes):
        if policy.me != self._peer:
            raise ContractError('selected_message_store_invalid')
        if self._repository is not None:
            repo, rid = self._repository['localName'], self._repository['repositoryId']
            remote = config['repos'].get(repo, {}).get('remote') or remotes.get(repo)
            if (policy.rid_of(repo) != rid or policy.local_of(rid) != repo
                    or remote is None or normalize_remote(remote) != self._repository['normalizedRemote']
                    or store.q1('SELECT repo FROM repos WHERE repo=?', (repo,)) is None):
                raise ContractError('selected_message_store_invalid')


class SelectedMessageDomain:
    """Host-private access to the existing domain; plugins receive wire handles."""
    def __init__(self, source, session, *, identity, scope, local_node):
        self._source, self.session = source, session
        self.me, self.node = source._peer, local_node
        self._scope = canonical_bytes(scope)
        self._legacy_identity = LegacyIdentityAdapter(identity.reader,
            local_source_hub_id=identity.reader._hub, scope=scope)
        self.hub = self

    @property
    def store(self):
        return self._source._store

    @property
    def policy(self):
        if getattr(self._source._worker, 'active', False):
            self._source._check_files()
        else:
            self._source.check_health()
        return self._source._policy

    @property
    def fcfg(self):
        return self.policy.cfg['federation']

    async def db(self, function, *args, **kwargs):
        return await self._source.db(function, *args, **kwargs)

    async def _current_identity_target(self, target):
        if target.startswith('virtual:'):
            return target, ()
        async def resolve():
            direct = await self.db(self.store.registration, target, True)
            canonical = await self.db(self.store.canonical_target, target, ('operator', 'hub'))
            try:
                registrations = (direct,) if direct is not None else tuple(
                    await self.db(self.store.recipient_registrations, canonical))
            except NoRecipients:
                # Let the message owner recheck the missing role and use its
                # existing operator fallback. Identity failures still propagate.
                return canonical, ()
            return canonical, await self._legacy_identity.bind(registrations)
        selected, _ = await resolve()
        current, bindings = await resolve()
        if selected != current:
            raise ContractError('capability_resource_stale')
        return current, bindings

    sender_of = Federation.sender_of
    address_of = Federation.address_of
    stage = Federation.stage
    publish = Federation.publish

    def kick(self):
        # The existing federation outbox worker owns delivery. Its normal polling
        # observes this same committed outbox; this host owns no second publisher.
        pass
