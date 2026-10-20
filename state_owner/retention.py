"""Validate retained authority storage and reserve admission headroom.

This policy requires a dedicated aggregate stream. That keeps competing writes
and quota admission behind the same subject condition. Owners derive the required
future record bound from their complete proposed state; this module enforces it.
"""
from dataclasses import dataclass

from agentmux_contracts import ContractError
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig

RECORD_CHARGE = 131_072


@dataclass(frozen=True)
class Retention:
    max_bytes: int
    reserve_bytes: int
    replicas: int = 1

    def __post_init__(self):
        if (type(self.max_bytes) is not int or type(self.reserve_bytes) is not int
                or not 131_072 <= self.reserve_bytes < self.max_bytes <= 107_374_182_400
                or type(self.replicas) is not int or self.replicas not in (1, 3)):
            raise ContractError('owner_retention_configuration')

    def stream_config(self, *, stream, subject):
        """For a separately authorized provisioner; the owner never calls add_stream."""
        return StreamConfig(name=stream, subjects=[subject], storage=StorageType.FILE,
                            retention=RetentionPolicy.LIMITS, discard=DiscardPolicy.NEW,
                            max_bytes=self.max_bytes, max_age=0, max_msgs=-1,
                            max_msgs_per_subject=-1, max_msg_size=65_536,
                            deny_delete=True, deny_purge=True, allow_rollup_hdrs=False,
                            allow_msg_ttl=False, num_replicas=self.replicas)

    def validate(self, info, *, stream, subject):
        config, state = info.config, info.state
        if (config.name != stream or config.subjects != [subject]
                or config.storage != StorageType.FILE or config.retention != RetentionPolicy.LIMITS
                or config.discard != DiscardPolicy.NEW or config.max_age not in (None, 0)
                or config.max_bytes != self.max_bytes or config.max_msg_size != 65_536
                or config.max_msgs not in (None, -1) or config.max_msgs_per_subject not in (None, -1)
                or not config.deny_delete or not config.deny_purge or config.allow_rollup_hdrs
                or config.allow_msg_ttl or config.num_replicas != self.replicas
                or config.allow_msg_schedules or config.allow_msg_counter
                or config.mirror or config.sources or config.subject_transform or config.republish
                or config.no_ack or config.sealed):
            raise ContractError('owner_retention_unsafe')
        if (type(state.last_seq) is not int or type(state.messages) is not int
                or state.last_seq < 0 or state.messages < 0 or state.num_deleted
                or (state.messages and state.first_seq != 1)
                or state.messages != state.last_seq):
            raise ContractError('owner_history_gap')
        if (type(state.bytes) is not int or state.bytes < 0
                or state.bytes > state.messages * 131_072):
            raise ContractError('owner_capacity_unverified')

    def admit(self, info, body_bytes, admission, *, completion_records=None):
        """Leave room for every required record after this proposed append.

        completion_records is a trusted domain bound, not a caller request field.
        It includes all outstanding obligations and their required receipt/claim/
        reconciliation writes. The owner must recompute it from the same candidate
        state and expected sequence, including after recovery and every conflict.
        """
        if admission not in ('bulk', 'completion', 'reconciliation'):
            raise ContractError('owner_admission_invalid')
        if (completion_records is not None and
                (type(completion_records) is not int or not 0 <= completion_records <= 9_007_199_254_740_991)):
            raise ContractError('owner_completion_budget_invalid')
        # Charge a full maximum record and framing allowance for every append.
        # This is deliberately conservative; it does not measure physical disk use.
        projected = (info.state.messages + 1) * RECORD_CHARGE
        remaining = (completion_records or 0) * RECORD_CHARGE
        limit = self.max_bytes
        if admission == 'bulk':
            limit = min(limit * 85 // 100, limit - self.reserve_bytes)
        if projected > limit or projected + remaining > self.max_bytes:
            raise ContractError('owner_capacity_reserved' if admission == 'bulk'
                                else 'owner_capacity_exhausted')

    def warning(self, info):
        return info.state.messages * 131_072 * 100 >= self.max_bytes * 70
