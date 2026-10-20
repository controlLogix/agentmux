"""Conditionally append complete owner records to retained JetStream history.

The receiving domain service authenticates and authorizes each command. It owns
business validation and must repeat it after a conflict. This module never runs
effects, grants authority, creates streams, deletes records or retries a proposal.
"""
from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from nats.js.errors import APIError, NotFoundError

from .retention import RECORD_CHARGE, Retention

MAX_RECORD_BYTES = 65_536
MAX_SEQUENCE = 9_007_199_254_740_991
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


@dataclass(frozen=True, repr=False)
class StreamIdentity:
    """Trusted enrollment/recovery input, never learned from an arbitrary read.

    minimum_sequence comes from retained provisioning/recovery history. Creation
    time detects recreation; the floor detects rollback only through that known
    revision. Neither establishes that an older backup has no external effects.
    """
    created: datetime
    minimum_sequence: int

    def __post_init__(self):
        if (not isinstance(self.created, datetime) or self.created.tzinfo is None
                or self.created.utcoffset() != timezone.utc.utcoffset(self.created)
                or type(self.minimum_sequence) is not int
                or not 0 <= self.minimum_sequence <= MAX_SEQUENCE):
            raise ContractError('owner_stream_identity_invalid')

    def __repr__(self):
        return '<StreamIdentity private>'


@dataclass(frozen=True, repr=False)
class OwnerBinding:
    hub_id: str
    owner_domain: str
    entity_id: str
    entity_kind: str
    scope: bytes

    def __post_init__(self):
        if (not all(isinstance(v, str) and _ID.fullmatch(v) for v in
                    (self.hub_id, self.owner_domain, self.entity_id, self.entity_kind))
                or type(self.scope) is not bytes):
            raise ContractError('owner_configuration_invalid')
        scope = strict_loads(self.scope)
        if (type(scope) is not dict or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or not isinstance(scope['organizationId'], str)
                or not _ID.fullmatch(scope['organizationId'])
                or any(v is not None and (not isinstance(v, str) or not _ID.fullmatch(v))
                       for v in (scope['projectId'], scope['workspaceId']))
                or (scope['workspaceId'] is not None and scope['projectId'] is None)):
            raise ContractError('owner_configuration_invalid')
        object.__setattr__(self, 'scope', canonical_bytes(scope))

    def __repr__(self):
        return '<OwnerBinding private>'


def owner_subject(binding):
    """Build a storage subject from validated opaque tokens, including null scope.

    An underscore cannot be an ID in v1, so it cannot collide with a real project
    or workspace. The provisioner uses this same exact subject for broker grants.
    """
    scope = strict_loads(binding.scope)
    return '.'.join(('amx', 'v1', 'h', binding.hub_id, 'o', scope['organizationId'],
                     'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_',
                     'ledger', binding.owner_domain, binding.entity_id))


@dataclass(frozen=True, repr=False)
class StoredRecord:
    record: bytes
    sequence: int
    replayed: bool = False

    def __repr__(self):
        return '<StoredRecord private>'


@dataclass(frozen=True, repr=False)
class Snapshot:
    records: Sequence[StoredRecord]
    sequence: int

    @property
    def latest(self):
        return self.records[-1] if self.records else None

    def __repr__(self):
        return '<Snapshot private>'


@dataclass(frozen=True)
class RecoveryProgress:
    cursor: int
    target: int
    ready: bool


def validate_record(raw, binding):
    if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
        raise ContractError('owner_record_size')
    record = strict_loads(raw)
    validate('owner-record', record)
    if ((record['ownerHubId'], record['ownerDomain'], record['entityId'], record['entityKind'])
            != (binding.hub_id, binding.owner_domain, binding.entity_id, binding.entity_kind)
            or canonical_bytes(record['operation']['scope']) != binding.scope):
        raise ContractError('owner_binding_mismatch')
    for effect in record['effects']:
        if payload_digest(effect['payload']) != effect['payloadDigest']:
            raise ContractError('owner_effect_digest')
    return record


def validate_history(records, binding):
    """Check a complete retained chain without interpreting or executing state."""
    previous, operations, record_ids, effects = 0, set(), set(), {}
    result = []
    for version, stored in enumerate(records, 1):
        if (not isinstance(stored, StoredRecord) or type(stored.sequence) is not int
                or not previous < stored.sequence <= MAX_SEQUENCE):
            raise ContractError('owner_history_invalid')
        record = validate_record(stored.record, binding)
        if (stored.sequence != version or record['previousRevision'] != previous
                or record['entityVersion'] != version):
            raise ContractError('owner_history_gap')
        operation_id = record['operation']['operationId']
        if operation_id in operations or record['recordId'] in record_ids:
            raise ContractError('owner_history_duplicate')
        operations.add(operation_id)
        record_ids.add(record['recordId'])
        for effect in record['effects']:
            content = canonical_bytes(effect)
            if effect['effectId'] in effects and effects[effect['effectId']] != content:
                raise ContractError('owner_effect_conflict')
            effects[effect['effectId']] = content
        result.append(StoredRecord(canonical_bytes(record), stored.sequence))
        previous = stored.sequence
    return Snapshot(tuple(result), previous)


def find_outcome(snapshot, operation_id, digest):
    if (not isinstance(operation_id, str) or not _ID.fullmatch(operation_id)
            or not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)):
        raise ContractError('owner_operation_invalid')
    for stored in snapshot.records:
        operation = strict_loads(stored.record)['operation']
        if operation['operationId'] == operation_id:
            if operation['payloadDigest'] != digest:
                raise ContractError('owner_operation_conflict')
            return StoredRecord(stored.record, stored.sequence, replayed=True)
    return None


class OwnerLedger:
    """Host-private helper over a preprovisioned, credential-scoped stream.

    Operation IDs are unique within the pinned owner aggregate. A service must
    bind the command target to that aggregate before calling this helper. It must
    not allocate a new aggregate to make a retry look like a new operation.
    """

    def __init__(self, jetstream, *, stream, subject, binding, retention, stream_identity,
                 timeout=3.0, max_history_records=100_000, max_history_bytes=67_108_864,
                 history=None, require_completion_budget=False):
        if (not isinstance(stream, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', stream)
                or not isinstance(subject, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', subject)
                or len(subject) > 512 or not isinstance(binding, OwnerBinding)
                or not isinstance(retention, Retention)
                or not isinstance(stream_identity, StreamIdentity)
                or type(timeout) not in (int, float) or not 0 < timeout <= 10
                or type(max_history_records) is not int or not 1 <= max_history_records <= 100_000
                or type(max_history_bytes) is not int or not 65_536 <= max_history_bytes <= 67_108_864
                or type(require_completion_budget) is not bool):
            raise ContractError('owner_configuration_invalid')
        if subject != owner_subject(binding):
            raise ContractError('owner_subject_mismatch')
        slots = retention.max_bytes // RECORD_CHARGE
        if history is not None:
            from .history import OwnerHistory
            if (not isinstance(history, OwnerHistory) or history.binding != binding
                    or history.source_identity.created != stream_identity.created):
                raise ContractError('owner_history_configuration')
            if history.max_records < slots or history.max_bytes < slots * MAX_RECORD_BYTES:
                raise ContractError('owner_history_capacity')
        elif require_completion_budget and (max_history_records < slots
                or max_history_bytes < slots * MAX_RECORD_BYTES):
            raise ContractError('owner_history_capacity')
        self._js, self._stream, self._subject = jetstream, stream, subject
        self._binding, self._retention, self._timeout = binding, retention, timeout
        self._identity = stream_identity
        self._minimum_sequence = stream_identity.minimum_sequence
        if history is not None:
            self._minimum_sequence = max(self._minimum_sequence, history.source_identity.minimum_sequence)
        self._max_records, self._max_bytes = max_history_records, max_history_bytes
        self._history = history
        self._anchored_cursor = 0
        self._require_completion_budget = require_completion_budget

    @property
    def completion_budget_required(self):
        return self._require_completion_budget

    def require_recovery_identity(self, identity):
        """Raise the trusted floor before replay or admission; never lower it.

        The receiving host obtains this identity from protected recovery inventory.
        This does not declare the broker recovered. Every later source observation
        still checks the creation identity and the retained minimum revision.
        """
        if not isinstance(identity, StreamIdentity) or identity.created != self._identity.created:
            raise ContractError('owner_recovery_required')
        self._minimum_sequence = max(self._minimum_sequence, identity.minimum_sequence)
        return StreamIdentity(self._identity.created, self._minimum_sequence)

    async def _call(self, awaitable):
        return await asyncio.wait_for(awaitable, self._timeout)

    async def _info(self):
        info = await self._call(self._js.stream_info(self._stream))
        self._retention.validate(info, stream=self._stream, subject=self._subject)
        if (info.created != self._identity.created or info.state.last_seq < self._minimum_sequence):
            raise ContractError('owner_recovery_required')
        return info

    async def current(self):
        """Read one consistent chain from the leader; fail closed on missing data."""
        try:
            operation = self._current_indexed() if self._history is not None else self._current()
            return await asyncio.wait_for(operation, self._timeout)
        except TimeoutError:
            raise ContractError('owner_unavailable') from None

    def _stored_message(self, message, *, sequence=None):
        if (getattr(message, 'subject', None) != self._subject
                or type(getattr(message, 'seq', None)) is not int
                or not 0 < message.seq <= MAX_SEQUENCE
                or (sequence is not None and message.seq != sequence)):
            raise ContractError('owner_history_invalid')
        value = validate_record(getattr(message, 'data', None), self._binding)
        return StoredRecord(canonical_bytes(value), message.seq)

    async def prepare_history(self, *, batch_size=128):
        """Verify a bounded source page without granting readiness or executing work.

        Call repeatedly during owner recovery until ready. Completed pages remain
        usable when a later page times out. A reopened cache starts unverified;
        only a separately verified checkpoint can supply an already checked prefix.
        """
        if self._history is None or type(batch_size) is not int or not 1 <= batch_size <= 256:
            raise ContractError('owner_history_configuration')
        try:
            async with asyncio.timeout(self._timeout):
                info = await self._info()
                target = info.state.last_seq
                if self._history.cursor > target or self._history.verified_cursor > target:
                    raise ContractError('owner_recovery_required')
                cursor = self._history.verified_cursor
                if cursor and cursor != self._anchored_cursor:
                    actual = self._stored_message(await self._call(self._js.get_msg(
                        self._stream, seq=cursor, direct=False)), sequence=cursor)
                    if actual.record != self._history.record(cursor).record:
                        raise ContractError('owner_history_corrupt')
                    self._anchored_cursor = cursor
                stop = min(target, cursor + batch_size)
                for sequence in range(cursor + 1, stop + 1):
                    stored = self._stored_message(await self._call(self._js.get_msg(
                        self._stream, seq=sequence, direct=False)), sequence=sequence)
                    self._history.verify_source(stored)
                    self._anchored_cursor = sequence
                await self._info()
                cursor = self._history.verified_cursor
                self._minimum_sequence = max(self._minimum_sequence, target)
                return RecoveryProgress(cursor, target, cursor == target)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except NotFoundError:
            raise ContractError('owner_history_gap') from None
        except Exception:
            raise ContractError('owner_unavailable') from None

    async def _current_indexed(self):
        try:
            progress = await self.prepare_history()
            if not progress.ready:
                raise ContractError('owner_history_recovery_required')
            if progress.cursor == 0:
                return Snapshot(self._history.records(0), 0)
            # Check the actual leader-backed tip, not just a stored query cursor.
            latest = self._stored_message(await self._call(self._js.get_msg(
                self._stream, subject=self._subject, direct=False)))
            if latest.sequence != progress.cursor:
                raise ContractError('owner_history_recovery_required')
            if latest.record != self._history.record(progress.cursor).record:
                raise ContractError('owner_history_corrupt')
            return Snapshot(self._history.records(progress.cursor), progress.cursor)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except NotFoundError:
            raise ContractError('owner_history_gap') from None
        except Exception:
            raise ContractError('owner_unavailable') from None

    async def _current(self):
        try:
            await self._info()
            try:
                message = await self._call(self._js.get_msg(
                    self._stream, subject=self._subject, direct=False))
            except NotFoundError:
                # An empty subject is safe only in a verified empty dedicated stream.
                info = await self._info()
                if info.state.last_seq != 0 or info.state.messages != 0:
                    raise ContractError('owner_history_gap')
                return Snapshot((), 0)
            records, total_bytes = [], 0
            while True:
                if (getattr(message, 'subject', None) != self._subject
                        or type(getattr(message, 'seq', None)) is not int
                        or not 0 < message.seq <= MAX_SEQUENCE
                        or type(getattr(message, 'data', None)) is not bytes):
                    raise ContractError('owner_history_invalid')
                total_bytes += len(message.data)
                if len(records) >= self._max_records or total_bytes > self._max_bytes:
                    raise ContractError('owner_history_limit')
                record = validate_record(message.data, self._binding)
                records.append(StoredRecord(canonical_bytes(record), message.seq))
                previous = record['previousRevision']
                if previous == 0:
                    break
                if not 0 < previous < message.seq:
                    raise ContractError('owner_history_invalid')
                message = await self._call(self._js.get_msg(
                    self._stream, seq=previous, direct=False))
                if message.seq != previous:
                    raise ContractError('owner_history_gap')
            snapshot = validate_history(reversed(records), self._binding)
            if snapshot.sequence != len(snapshot.records):
                raise ContractError('owner_history_gap')
            # No deletion or retention change may hide the suffix read above.
            await self._info()
            self._minimum_sequence = max(self._minimum_sequence, snapshot.sequence)
            return snapshot
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except NotFoundError:
            raise ContractError('owner_history_gap') from None
        except Exception:
            raise ContractError('owner_unavailable') from None

    async def outcome(self, operation_id, payload_digest):
        snapshot = await self.current()
        return await self._find_outcome(snapshot, operation_id, payload_digest)

    async def _find_outcome(self, snapshot, operation_id, digest):
        if self._history is None:
            return find_outcome(snapshot, operation_id, digest)
        result = self._history.outcome(operation_id, digest)
        if result is not None:
            try:
                actual = self._stored_message(await self._call(self._js.get_msg(
                    self._stream, seq=result.sequence, direct=False)), sequence=result.sequence)
                if actual.record != result.record:
                    raise ContractError('owner_history_corrupt')
            except asyncio.CancelledError:
                raise
            except ContractError:
                raise
            except Exception:
                raise ContractError('owner_history_gap') from None
        return result

    async def append(self, record, *, expected_sequence, admission='bulk', valid_until=None,
                     expected_target_version=None, completion_records=None):
        """Commit once; the caller has already validated and authorized the state.

        A conditional conflict never retries. After owner_revision_conflict the
        service must reread, reauthorize, and rebuild its proposal. After
        owner_commit_uncertain it must reconcile the original operation identity.
        Strict composition requires completion_records for each new append: an
        upper bound on all future required writes after this proposed transition,
        derived by the trusted owner from its complete durable candidate state.
        Retained replay consumes no new record or completion capacity.
        """
        if type(expected_sequence) is not int or not 0 <= expected_sequence <= MAX_SEQUENCE:
            raise ContractError('owner_revision_invalid')
        raw = canonical_bytes(record)
        value = validate_record(raw, self._binding)
        if expected_target_version is not None:
            target_version_allowed = (
                self._binding.entity_kind == 'definition-catalog'
                or (self._binding.owner_domain, self._binding.entity_kind)
                in {('federation-board-operations', 'attempt'),
                    ('orchestration-operations', 'attempt'),
                    ('ordinary-secret-uses', 'effect'),
                    ('execution', 'attempt'),
                    ('policy-evaluations', 'policy-evaluation')})
            if (not target_version_allowed
                    or type(expected_target_version) is not int
                    or not 0 <= expected_target_version <= MAX_SEQUENCE):
                raise ContractError('owner_target_version_invalid')
        if (valid_until is not None and
                (not isinstance(valid_until, datetime) or valid_until.tzinfo is None
                 or valid_until.utcoffset() != timezone.utc.utcoffset(valid_until))):
            raise ContractError('owner_authorization_deadline_invalid')
        # Never extend either the command deadline or a shorter current decision.
        try:
            command_deadline = datetime.fromisoformat(value['operation']['deadline'])
        except (ValueError, TypeError):
            raise ContractError('owner_authorization_deadline_invalid') from None
        deadline = min(command_deadline, valid_until) if valid_until is not None else command_deadline
        snapshot = await self.current()
        existing = await self._find_outcome(snapshot, value['operation']['operationId'],
                                           value['operation']['payloadDigest'])
        if existing is not None:
            return existing
        if self._require_completion_budget and completion_records is None:
            raise ContractError('owner_completion_budget_required')
        if snapshot.sequence != expected_sequence:
            raise ContractError('owner_revision_conflict')
        target_version = len(snapshot.records) if expected_target_version is None else expected_target_version
        if (value['previousRevision'] != expected_sequence
                or value['entityVersion'] != len(snapshot.records) + 1
                or (value['outcome'] == 'committed'
                    and value['operation']['expectedVersion'] != target_version)):
            raise ContractError('owner_revision_invalid')
        if (value['outcome'] == 'rejected' and snapshot.latest is not None
                and value['state'] != strict_loads(snapshot.latest.record)['state']):
            raise ContractError('owner_rejected_state_changed')
        # Also prevents reusing a record/effect identity with changed content.
        proposed = StoredRecord(raw, expected_sequence + 1)
        if self._history is None:
            validate_history((*snapshot.records, proposed), self._binding)
        else:
            if self._history.verified_cursor != expected_sequence:
                raise ContractError('owner_revision_conflict')
            self._history.check_next(proposed)
        try:
            info = await self._info()
            self._retention.admit(info, len(raw), admission, completion_records=completion_records)
            if datetime.now(timezone.utc) >= deadline:
                raise ContractError('owner_authorization_expired')
            ack = await self._call(self._js.publish(self._subject, raw, headers={
                'Nats-Expected-Stream': self._stream,
                'Nats-Expected-Last-Subject-Sequence': str(expected_sequence),
            }))
        except asyncio.CancelledError:
            # Cancellation is not evidence that the broker rejected this append.
            raise
        except ContractError:
            raise
        except APIError as exc:
            if exc.err_code == 10071:
                raise ContractError('owner_revision_conflict') from None
            # A broker error is not a committed outcome or permission to dispatch.
            raise ContractError('owner_append_rejected') from None
        except Exception:
            raise ContractError('owner_commit_uncertain') from None
        if (getattr(ack, 'stream', None) != self._stream
                or type(getattr(ack, 'seq', None)) is not int
                or ack.seq != expected_sequence + 1 or ack.seq > MAX_SEQUENCE
                or getattr(ack, 'duplicate', False)):
            raise ContractError('owner_commit_uncertain')
        self._minimum_sequence = max(self._minimum_sequence, ack.seq)
        stored = StoredRecord(raw, ack.seq)
        if self._history is not None:
            try:
                if self._history.verified_cursor < ack.seq:
                    self._history.append_verified(stored)
                    self._anchored_cursor = ack.seq
            except ContractError:
                # The broker commit is known. A failed query-cache update cannot
                # turn it into a rejected command; the next read must repair it.
                pass
        return stored
