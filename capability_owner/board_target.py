"""Protected identity of an existing board card, separate from its alias."""
from dataclasses import dataclass
import re

from agentmux_contracts import ContractError, canonical_bytes
from state_owner.ledger import StreamIdentity


@dataclass(frozen=True, repr=False)
class BoardTargetBinding:
    repository_id: str
    card_key: str
    stream_identity: StreamIdentity
    domain: str = ''

    def __post_init__(self):
        if (type(self.repository_id) is not str or not re.fullmatch(r'r[a-f0-9]{12}',self.repository_id)
                or type(self.card_key) is not str or not re.fullmatch(r'[A-Z0-9_-]{1,96}',self.card_key)
                or not isinstance(self.stream_identity,StreamIdentity) or type(self.domain) is not str
                or self.domain and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',self.domain)):
            raise ContractError('board_target_configuration')

    def __repr__(self):
        return '<BoardTargetBinding private>'

    @property
    def canonical(self):
        return canonical_bytes({'bucket':'am_board','repositoryId':self.repository_id,
            'cardKey':self.card_key,'domain':self.domain,
            'streamCreated':self.stream_identity.created.isoformat(timespec='microseconds').replace('+00:00','Z'),
            'minimumSequence':self.stream_identity.minimum_sequence})
