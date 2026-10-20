"""Read an enrolled existing am_board card without copying its authority."""
from dataclasses import dataclass, field, InitVar
import re

from agentmux_contracts import ContractError, strict_loads
from hub.fed.board_services import BUCKET, SharedBoardStore, _ScopedBoardKV
from hub.fed.session import FederationSession
from state_owner.ledger import OwnerBinding, StreamIdentity


@dataclass(frozen=True, repr=False)
class FederationBoardResource:
    """Host-only alias to one existing card, its repository and original session.

    The reference revision is the real am_board KV revision. The alias does not
    rename the stored key. Neither request JSON nor a plugin selects these pins.
    """
    binding: OwnerBinding = field(repr=False)
    board: SharedBoardStore = field(repr=False)
    repository: str = field(repr=False)
    repository_id: str = field(repr=False)
    card_key: str = field(repr=False)
    stream_identity: StreamIdentity = field(repr=False)
    _bootstrap: InitVar[object] = None
    _session: object = field(init=False, repr=False)
    _jetstream: object = field(init=False, repr=False)
    _sequence: int = field(init=False, repr=False)

    def __post_init__(self, _bootstrap):
        if (not isinstance(self.binding, OwnerBinding)
                or self.binding.owner_domain != 'federation-board'
                or self.binding.entity_kind != 'board-card'
                or not isinstance(self.board, SharedBoardStore)
                or not isinstance(self.stream_identity, StreamIdentity)
                or type(self.repository) is not str or not self.repository
                or type(self.repository_id) is not str
                or re.fullmatch(r'r[a-f0-9]{12}', self.repository_id) is None
                or type(self.card_key) is not str
                or re.fullmatch(r'[A-Z0-9_-]{1,96}', self.card_key) is None
                or strict_loads(self.binding.scope)['projectId'] is None):
            raise ContractError('capability_owner_configuration')
        owner = self.board._owner
        if not isinstance(owner.session, FederationSession):
            raise ContractError('capability_owner_configuration')
        object.__setattr__(self, '_session', owner.session)
        object.__setattr__(self, '_jetstream', owner.js)
        object.__setattr__(self, '_sequence', self.stream_identity.minimum_sequence)
        if _bootstrap is None:
            self._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap, self)

    def __repr__(self):
        return '<FederationBoardResource private>'

    def _current(self):
        owner = self.board._owner
        if (owner.session is not self._session or owner.js is not self._jetstream
                or owner.policy.rid_of(self.repository) != self.repository_id
                or owner.policy.local_of(self.repository_id) != self.repository):
            raise ContractError('capability_resource_stale')
        self._session.check_open()
        return owner

    async def _stream(self):
        self._current()
        info = await self._jetstream.stream_info('KV_' + BUCKET)
        self._current()
        if (info.config.name != 'KV_' + BUCKET
                or info.config.subjects != ['$KV.' + BUCKET + '.>']
                or info.created != self.stream_identity.created
                or info.state.last_seq < self._sequence):
            raise ContractError('capability_resource_stale')
        object.__setattr__(self, '_sequence', max(self._sequence, info.state.last_seq))

    async def read(self, revision):
        await self._stream()
        kv = await self._key_value()
        key = self.repository_id + '.card.' + self.card_key
        entry = await kv.get(key)
        self._current()
        await self._stream()
        if (entry.bucket != BUCKET or entry.key != key
                or type(entry.revision) is not int or entry.revision != revision
                or type(entry.value) is not bytes or len(entry.value) > 45000):
            raise ContractError('capability_resource_stale')
        card = strict_loads(entry.value)
        if (type(card) is not dict or card.get('rid') != self.repository_id
                or card.get('key') != self.card_key):
            raise ContractError('capability_resource_stale')
        # Return original bytes, including every unknown field, history and ID.
        # The existing owner retains its KV sequence, mirror and audit behavior.
        return entry.value

    async def _key_value(self):
        # Use this resource's pinned connection rather than a legacy owner's KV
        # cache, which may belong to a different publisher credential.
        owner=self._current()
        kv=await self._jetstream.key_value(BUCKET)
        self._current()
        return _ScopedBoardKV(owner,kv,self.repository_id,self.repository)
