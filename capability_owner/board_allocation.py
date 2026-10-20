"""Prepare a prefix allocation without granting authority or dispatching writes."""
from dataclasses import dataclass,field,InitVar
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.fed.board_services import PreparedBoardAddInput, PreparedBoardChange, SharedBoardStore, _BoardOperations
from hub.fed.session import FederationSession
from state_owner.ledger import MAX_SEQUENCE, StreamIdentity,OwnerBinding
from .board_journal import candidate_digest, claim_marker


@dataclass(frozen=True,repr=False)
class BoardAllocationTarget:
    repository_id: str
    counter_prefix: str
    stream_identity: StreamIdentity
    domain: str = ''

    def __post_init__(self):
        if (type(self.repository_id) is not str or not re.fullmatch(r'r[a-f0-9]{12}',self.repository_id)
                or type(self.counter_prefix) is not str or not re.fullmatch(r'[A-Z0-9_-]{1,64}',self.counter_prefix)
                or not isinstance(self.stream_identity,StreamIdentity)
                or type(self.domain) is not str
                or self.domain and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',self.domain)):
            raise ContractError('board_allocation_configuration')

    def __repr__(self):
        return '<BoardAllocationTarget private>'

    @property
    def counter_subject(self):
        return '$KV.am_board.'+self.repository_id+'.seq.'+self.counter_prefix

    @property
    def canonical(self):
        return canonical_bytes({'bucket':'am_board','repositoryId':self.repository_id,
            'counterPrefix':self.counter_prefix,'domain':self.domain,
            'streamCreated':self.stream_identity.created.isoformat(timespec='microseconds').replace('+00:00','Z'),
            'minimumSequence':self.stream_identity.minimum_sequence})


@dataclass(frozen=True,repr=False)
class BoardAllocationResource:
    binding: OwnerBinding
    board: SharedBoardStore
    repository: str
    target: BoardAllocationTarget
    _bootstrap: InitVar[object] = None
    _session: object = field(init=False,repr=False)
    _jetstream: object = field(init=False,repr=False)
    _sequence: int = field(init=False,repr=False)

    def __post_init__(self, _bootstrap):
        if (type(self.target) is not BoardAllocationTarget or not isinstance(self.binding,OwnerBinding)
                or (self.binding.owner_domain,self.binding.entity_kind)!=('federation-board','board-prefix')
                or strict_loads(self.binding.scope)['projectId'] is None
                or not isinstance(self.board,SharedBoardStore)
                or type(self.repository) is not str or not self.repository
                or not isinstance(self.board._owner.session,FederationSession)):
            raise ContractError('board_allocation_configuration')
        object.__setattr__(self,'_session',self.board._owner.session)
        object.__setattr__(self,'_jetstream',self.board._owner.js)
        object.__setattr__(self,'_sequence',self.target.stream_identity.minimum_sequence)
        if _bootstrap is None:
            self._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap, self)

    def __repr__(self):
        return '<BoardAllocationResource private>'

    @property
    def repository_id(self):
        return self.target.repository_id

    def _current(self):
        owner=self.board._owner
        prefix='$JS.'+self.target.domain+'.API' if self.target.domain else '$JS.API'
        if (owner.session is not self._session or owner.js is not self._jetstream
                or owner.policy.rid_of(self.repository)!=self.repository_id
                or owner.policy.local_of(self.repository_id)!=self.repository
                or owner.policy.board_prefix(self.repository)!=self.target.counter_prefix
                or getattr(self._jetstream,'_prefix',None)!=prefix):
            raise ContractError('board_allocation_resource_stale')
        self._session.check_open()
        return owner

    async def _stream(self,floor):
        self._current()
        info=await self._jetstream.stream_info('KV_am_board')
        self._current()
        if (info.config.name!='KV_am_board' or info.config.subjects!=['$KV.am_board.>']
                or info.created!=self.target.stream_identity.created
                or type(info.state.last_seq) is not int
                or info.state.last_seq<max(floor,self._sequence)):
            raise ContractError('board_allocation_source_recovery_required')
        object.__setattr__(self,'_sequence',info.state.last_seq)


@dataclass(frozen=True,repr=False)
class PreparedBoardAllocation:
    target: BoardAllocationTarget
    counter_revision: int
    counter_value: bytes | None
    observed_sequence: int
    number: int
    candidate: PreparedBoardChange

    def __repr__(self):
        return '<PreparedBoardAllocation private>'

    @property
    def key(self):
        return self.target.counter_prefix+'-'+str(self.number)

    @property
    def counter_bytes(self):
        return str(self.number).encode('ascii')


def prepare_allocation(target,envelope,prepared_input,*,counter_revision,counter_value,
                       observed_sequence,context,by,at):
    """Freeze the actual observation and candidate before the durable claim.

    The receiving owner must obtain these observations from its pinned broker,
    reject tombstones and existing target keys, authorize and retain the complete
    plan before dispatch. This preparation does no I/O and grants no permission.
    """
    if (type(target) is not BoardAllocationTarget or type(prepared_input) is not PreparedBoardAddInput
            or type(counter_revision) is not int or not 0<=counter_revision<=MAX_SEQUENCE
            or type(observed_sequence) is not int or not max(counter_revision,
                target.stream_identity.minimum_sequence)<=observed_sequence<=MAX_SEQUENCE
            or (counter_revision==0)!=(counter_value is None)
            or counter_value is not None and (type(counter_value) is not bytes or len(counter_value)>128)):
        raise ContractError('board_allocation_invalid')
    validate('message-envelope',envelope)
    validate('federation-board-command',envelope['payload'])
    if envelope['contractId']!='federation-board-command' or envelope['payload']['input']['command']!='add':
        raise ContractError('board_allocation_invalid')
    try:
        previous=0 if counter_value is None else int(counter_value)
    except (ValueError,TypeError):
        raise ContractError('board_counter_recovery_required') from None
    if not 0<=previous<MAX_SEQUENCE:
        raise ContractError('board_counter_recovery_required')
    number=previous+1
    key=target.counter_prefix+'-'+str(number)
    candidate=_BoardOperations().prepare_add(context,target.repository_id,key,prepared_input,
        by=by,at=at,operation_marker=claim_marker(envelope))
    candidate_digest(candidate.value)
    return PreparedBoardAllocation(target,counter_revision,counter_value,observed_sequence,number,candidate)
