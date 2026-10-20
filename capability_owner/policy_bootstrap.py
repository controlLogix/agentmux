"""Private structural admission while selected policy startup is still owned."""
import asyncio
from datetime import datetime
from weakref import WeakKeyDictionary

from agentmux_contracts import ContractError, canonical_bytes, strict_loads

_PERMITS = WeakKeyDictionary()
_JOBS = WeakKeyDictionary()


def _refuse():
    raise ContractError('selected_policy_bootstrap_invalid')


class PolicyResourceBootstrap:
    """A source-issued startup permit, never a runtime storage authority."""
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Selected source startup is required')

    def __repr__(self):
        return '<PolicyResourceBootstrap private>'

    def _state(self):
        state = _PERMITS.get(self)
        if state is None:
            _refuse()
        source, host, transition, task, name, declaration, store, database, policy, generation = state
        if (task.done() or host._closed or host._ready or host._starting is not task
                or transition._closed or transition._owner._closed or transition._uncertain is not None
                or source._closed or source._store is not store
                or source._database_identity != database or source._policy_identity != policy
                or source._policy_generation != generation or source._policy_paused or source._policy_replacing
                or source._policy_transition is not transition or transition._selected_host is not host
                or source not in transition._sources
                or host._preconstructed_sources.get(name) is not source
                or canonical_bytes(host._selection.policy['storage'][name]) != declaration):
            _refuse()
        if not getattr(source._worker, 'active', False) and asyncio.current_task() is not task and asyncio.current_task() not in _JOBS.get(self, ()):
            _refuse()
        source._check_files()
        return state

    def expire(self):
        _PERMITS.pop(self, None)

    async def close(self):
        self.expire()
        pending = tuple(_JOBS.get(self, ()))
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def _start_owned(self, operation, *args, **kwargs):
        self._state()
        task = asyncio.create_task(operation(*args, **kwargs))
        jobs = _JOBS.setdefault(self, set())
        jobs.add(task)
        def complete(done):
            jobs.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(complete)
        return task

    async def _owned(self, operation, *args, **kwargs):
        task = self._start_owned(operation, *args, **kwargs)
        await asyncio.wait({task})
        return task.result()

    def repository_id(self, owner, repository):
        source, *_ = self._state()
        if getattr(owner, '_source', None) is not source or owner.store is not source._store:
            _refuse()
        selected = source._repository
        state = self._state()
        if state[4] == 'work' and getattr(owner, '_selection', None) is state[1]._selection:
            _, _, selected, scope = owner._selection.work_channel_projection(strict_loads(owner._channel_ref))
            if canonical_bytes(scope) != owner._scope or canonical_bytes(selected) != owner._bound_repository:
                _refuse()
        if repository is None:
            if selected is not None:
                _refuse()
            return None
        if selected is None or selected['localName'] != repository:
            _refuse()
        return selected.get('repositoryId')

    def check(self, resource):
        state = self._state()
        source, host, _, _, name, raw, store, *_ = state
        selected = strict_loads(raw)
        owner = resource.board._owner if name == 'board' else resource._owner
        if getattr(owner, '_audit' if name == 'board' else '_source', None) is not source:
            _refuse()
        repository, scope = selected['repository'], host._selection.policy['storage']['scope']
        if name == 'work' and getattr(owner, '_selection', None) is not None:
            if owner._selection is not host._selection:
                _refuse()
            _, _, repository, scope = host._selection.work_channel_projection(strict_loads(owner._channel_ref))
            if canonical_bytes(repository) != owner._bound_repository:
                _refuse()
        if (resource.binding.hub_id != host._authority._hub
                or resource.binding.scope != canonical_bytes(scope)
                or resource.repository != (None if repository is None else repository['localName'])
                or resource.repository_id != (None if repository is None else repository.get('repositoryId'))):
            _refuse()
        resource._session.check_open()
        if owner.session is not resource._session:
            _refuse()
        if name == 'board':
            from .board_allocation import BoardAllocationResource
            from .federation_board import FederationBoardResource
            if owner.js is not resource._jetstream:
                _refuse()
            stream = resource.target.stream_identity if type(resource) is BoardAllocationResource else resource.stream_identity
            pinned = selected['kvStreamIdentity']
            if (stream.created != datetime.fromisoformat(pinned['created'])
                    or stream.minimum_sequence != pinned['minimumSequence']):
                _refuse()
            role = 'allocationPublisher' if type(resource) is BoardAllocationResource else 'cardPublisher'
            domain = selected[role]['connection']['jetstreamDomain'] or ''
            if getattr(resource._jetstream, '_prefix', None) != ('$JS.' + domain + '.API' if domain else '$JS.API'):
                _refuse()
            if type(resource) is BoardAllocationResource:
                if resource.target.domain != domain:
                    _refuse()
                if (resource.binding.entity_id != selected['allocationPublisher']['ledger']['entityId']
                        or resource.target.counter_prefix != selected['repository']['counterPrefix']):
                    _refuse()
            elif type(resource) is FederationBoardResource:
                if resource.binding.entity_id != selected['resourceRef']['id'] or resource.card_key != selected['cardKey']:
                    _refuse()
            else:
                _refuse()
        else:
            from .messages import MessageStorageResource
            from .knowledge import KnowledgeStorageResource
            from .code import CodeStorageResource
            expected = {'messages': MessageStorageResource, 'knowledge': KnowledgeStorageResource,
                'code': CodeStorageResource}.get(name)
            if name == 'work':
                from .work import WorkStorageResource
                expected = WorkStorageResource
            if type(resource) is not expected:
                _refuse()
            if resource._store is not store or owner.store is not store:
                _refuse()
            matches = [c for c in selected['channels'] if c['resourceRef']['id'] == resource.binding.entity_id]
            if len(matches) != 1:
                _refuse()
            channel = matches[0]
            descriptor = strict_loads(resource._journal.binding)
            for key in ('actors', 'pluginIdentityRef', 'instanceId', 'initialSource'):
                if descriptor.get(key) != channel[key]:
                    _refuse()
            if (name == 'messages' or 'legacyActors' in descriptor) and descriptor.get('legacyActors', []) != channel.get('legacyActors', []):
                _refuse()
            if name == 'messages':
                if descriptor['peer'] != channel['peer']:
                    _refuse()
            elif name == 'knowledge':
                actors = [{'identityRef': strict_loads(a.identity_ref), 'transportRef': strict_loads(a.transport_ref),
                    'caller': a.caller, 'grants': strict_loads(a.grants)} for a in resource._legacy_actors]
                if (actors != channel.get('legacyActors', [])
                        or [r.binding.entity_id for r in resource._message_sources]
                            != [r['id'] for r in channel.get('messageSources', [])]
                        or [item.binding.entity_id for item in (
                            tuple(pin.resource for pin in resource._work_capture_sources)
                            if hasattr(resource, '_work_capture_sources')
                            else resource._work_source_declarations)]
                            != [r['id'] for r in channel.get('workSources', [])]):
                    _refuse()
                if owner.me != selected['localPeer'] or owner.node != selected['localNode']:
                    _refuse()
            elif name in ('code', 'work'):
                actors = [{'identityRef': strict_loads(a.identity_ref), 'transportRef': strict_loads(a.transport_ref),
                    'caller': a.caller, 'grants': strict_loads(a.grants)} for a in resource._legacy_actors]
                if (actors != channel.get('legacyActors', [])
                        or owner.me != selected['localPeer'] or owner.node != selected['localNode']):
                    _refuse()
            else:
                _refuse()
        return resource

    async def submit(self, function, *args, **kwargs):
        return await self._owned(self._submit, function, *args, **kwargs)

    async def _submit(self, function, *args, **kwargs):
        source = self._state()[0]
        def run():
            self._state()
            result = function(*args, **kwargs)
            self._state()
            return result
        result = await source._submit(run, _admit_store=True)
        self._state()
        return result

    async def validate(self, resource, revision_floor):
        return await self._owned(self._validate, resource, revision_floor)

    async def _validate(self, resource, revision_floor):
        """Check retained data without disclosing it or granting live access."""
        self.check(resource)
        if type(revision_floor) is not int or revision_floor < 1:
            _refuse()
        if self._state()[4] == 'board':
            info = await resource._jetstream.stream_info('KV_am_board')
            self.check(resource)
            if (info.config.name != 'KV_am_board' or info.config.subjects != ['$KV.am_board.>']
                    or info.created != resource.stream_identity.created
                    or info.state.last_seq < resource._sequence):
                _refuse()
            kv = await resource._jetstream.key_value('am_board')
            self.check(resource)
            key = resource.repository_id + '.card.' + resource.card_key
            entry = await kv.get(key)
            self.check(resource)
            if (entry.bucket != 'am_board' or entry.key != key or type(entry.revision) is not int
                    or entry.revision < revision_floor or type(entry.value) is not bytes or len(entry.value) > 45000):
                _refuse()
            card = strict_loads(entry.value)
            if type(card) is not dict or card.get('rid') != resource.repository_id or card.get('key') != resource.card_key:
                _refuse()
            final = await resource._jetstream.stream_info('KV_am_board')
            self.check(resource)
            if (final.config.name != info.config.name or final.config.subjects != info.config.subjects
                    or final.created != info.created or final.state.last_seq < max(info.state.last_seq, entry.revision)):
                _refuse()
            object.__setattr__(resource, '_sequence', max(resource._sequence, final.state.last_seq))
        else:
            def read():
                self.check(resource)
                state = resource._journal.current()
                if state['revision'] < revision_floor:
                    _refuse()
                selected = state['source']
                if selected is None:
                    value = {'formatVersion': 1, 'source': None}
                elif self._state()[4] == 'messages':
                    if selected['kind'] == 'message':
                        value = resource._store.q1('SELECT * FROM messages WHERE id=?', (selected['id'],))
                    elif selected['kind'] == 'publication':
                        value = resource._store.q1('SELECT * FROM fed_outbox WHERE msg_id=?', (selected['id'],))
                    else:
                        _refuse()
                else:
                    value = resource._read_source(selected)
                if value is None or len(canonical_bytes(value)) > 45000:
                    _refuse()
            await self.submit(read)
        self.check(resource)


def _issue(source, selected_host, transition, declaration):
    """Called only by the actual source's startup issuance method."""
    from .selected_storage import SelectedStorageHost
    from .federation_policy_transition import FederationPolicyTransition
    if (type(selected_host) is not SelectedStorageHost or type(transition) is not FederationPolicyTransition
            or declaration not in ('board', 'messages', 'knowledge', 'code', 'work')
            or selected_host._starting is not asyncio.current_task()
            or transition not in selected_host._policy_transitions
            or source._policy_generation < 1):
        _refuse()
    permit = object.__new__(PolicyResourceBootstrap)
    _PERMITS[permit] = (source, selected_host, transition, asyncio.current_task(), declaration,
        canonical_bytes(selected_host._selection.policy['storage'][declaration]), source._store,
        source._database_identity, source._policy_identity, source._policy_generation)
    permit._state()
    return permit


def check_bootstrap(permit, resource):
    if type(permit) is not PolicyResourceBootstrap:
        _refuse()
    return permit.check(resource)
