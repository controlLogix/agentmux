"""Retained authority barrier for a legacy SQLite to owner-ledger cutover.

This component records a fence and the point after which the old writer cannot
be reopened. It does not activate target writers or implement reverse migration.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import threading

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot
from .backup_host import _native_guard
from .checkpoints import _publish, _read
from .ledger import (MAX_SEQUENCE, OwnerBinding, OwnerLedger, StoredRecord, StreamIdentity,
                     find_outcome, validate_record)
from .recovery import _binding


_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
_ACTIONS = {
    'record-source-fence': 'source-fenced',
    'request-recovery': 'source-recovery-authorized',
    'open-target-admission': 'target-admission-open',
    'fence-target': 'target-fenced',
}


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def authority_switch_id(source):
    """Return the stable target aggregate for one exact source fence."""
    validate('authority-switch', {'action': 'record-source-fence',
        'switchId': 'switch_'+'0'*64, 'source': source})
    return 'switch_' + payload_digest({'format': 'amx-authority-switch-identity-v1',
        'source': source}).split(':', 1)[1]


def _state_for(payload, version, prior=None):
    phase = _ACTIONS[payload['action']]
    if version == 1:
        return {'format': 'amx-authority-switch-v1', 'switchId': payload['switchId'],
            'phase': phase, 'operationAction': payload['action'], 'source': payload['source'], 'targetAdmissionRevision': None,
            'targetFenceRevision': None, 'reverseEvidence': None}
    state = dict(prior)
    state['phase'] = phase
    state['operationAction'] = payload['action']
    if phase == 'target-admission-open':
        state['targetAdmissionRevision'] = version
    elif phase == 'target-fenced':
        state['targetFenceRevision'] = version
    return state


def validate_authority_switch_record(stored, binding):
    """Validate one retained switch revision without granting recovery."""
    try:
        if (not isinstance(stored, StoredRecord) or not isinstance(binding, OwnerBinding)
                or (binding.owner_domain, binding.entity_kind) != ('authority-switch', 'authority-switch')):
            raise ValueError()
        record = validate_record(stored.record, binding)
        state = record['state']
        validate('authority-switch-state', state)
        version = record['entityVersion']
        allowed = {(1, 'source-fenced'), (2, 'source-recovery-authorized'),
            (2, 'target-admission-open'), (3, 'target-fenced')}
        if ((version, state['phase']) not in allowed
                or state['switchId'] != binding.entity_id
                or record['previousRevision'] != version-1
                or record['operation']['expectedVersion'] != version-1
                or record['operation']['payloadDigest'] != payload_digest({'action': state['operationAction'],
                    'switchId': state['switchId'], 'source': state['source']})
                or _ACTIONS.get(state['operationAction']) != state['phase']
                or state['targetAdmissionRevision'] != (2 if state['phase'] in
                    ('target-admission-open', 'target-fenced') else None)
                or state['targetFenceRevision'] != (3 if version == 3 else None)
                or state['reverseEvidence'] is not None
                or record['outcome'] != 'committed' or record['effects'] or record['artifacts']
                or record['repository'] is not None
                or record.get('authorizationDecision', {}).get('contractId') != 'authority-switch'):
            raise ValueError()
        validate('authority-switch', {'action': state['operationAction'],
            'switchId': state['switchId'], 'source': state['source']})
        return record
    except Exception:
        raise ContractError('authority_switch_record_invalid') from None


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedLegacyRecoveryPermit:
    _seal: object
    _receipt: bytes
    _request: bytes

    def __repr__(self):
        return '<VerifiedLegacyRecoveryPermit pre-cutover-abort>'

    @property
    def receipt(self):
        return strict_loads(self._receipt)

    def _matches(self, owner, *, source, switch_id, stream_identity, now):
        try:
            value = strict_loads(self._receipt)
            return (type(owner) is AuthoritySwitchOwner and self._seal is owner._permit_seal
                and value['decision'] == 'pre-cutover-abort'
                and value['switchRef']['id'] == switch_id
                and value['source'] == source
                and value['stream'] == {'created': _stamp(stream_identity.created),
                    'minimumSequence': stream_identity.minimum_sequence}
                and isinstance(now, datetime) and now.tzinfo is not None
                and now.utcoffset() == timezone.utc.utcoffset(now)
                and now < datetime.fromisoformat(value['validUntil']))
        except Exception:
            return False


@dataclass(frozen=True, repr=False)
class AuthoritySwitchObservation:
    stored: StoredRecord
    stream_identity: StreamIdentity


class AuthoritySwitchHost:
    """Private no-replace inventory of every observed switch revision."""
    def __init__(self, directory, *, binding, stream_identity):
        try:
            path = Path(directory)
            if (not path.is_absolute() or str(path) != os.path.realpath(path)
                    or not isinstance(binding, OwnerBinding)
                    or (binding.owner_domain, binding.entity_kind) != ('authority-switch', 'authority-switch')
                    or not isinstance(stream_identity, StreamIdentity)):
                raise ValueError()
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError()
            _native_guard(fd, directory=True)
            self._root = path
            self._identity = info.st_dev, info.st_ino
            self._binding, self._stream_identity = binding, stream_identity
            self._prefix = 'authority-switch-' + hashlib.sha256(canonical_bytes(
                _binding(binding))).hexdigest() + '-'
            self._lock = threading.RLock()
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except (NameError, OSError):
                pass
            raise ContractError('authority_switch_host_configuration') from None

    def __repr__(self):
        return '<AuthoritySwitchHost private>'

    def _open(self):
        fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if ((info.st_dev, info.st_ino) != self._identity or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(fd)
            raise ValueError()
        _native_guard(fd, directory=True)
        return fd

    @contextmanager
    def _custody(self):
        with self._lock:
            directory = lock = None
            try:
                directory = self._open()
                lock = os.open('.authority-switch.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                    0o600, dir_fd=directory)
                meta = os.fstat(lock)
                if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                        or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1):
                    raise ValueError()
                _native_guard(lock)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield directory
            finally:
                if lock is not None:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                    finally:
                        os.close(lock)
                if directory is not None:
                    os.close(directory)

    def _encode(self, stored):
        record = validate_authority_switch_record(stored, self._binding)
        return canonical_bytes({'format': 'amx-authority-switch-observation-v1',
            'binding': _binding(self._binding),
            'stream': {'created': self._stream_identity.created.isoformat(),
                'minimumSequence': stored.sequence},
            'sequence': stored.sequence, 'recordDigest': payload_digest(record),
            'record': record})

    def _entries(self, directory):
        values = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.startswith(self._prefix):
                    continue
                if not re.fullmatch(re.escape(self._prefix)+r'[1-3]-[0-9a-f]{64}\.json', entry.name):
                    raise ValueError()
                raw = _read(directory, entry.name, 65_536, admit=_native_guard)
                value = strict_loads(raw)
                sequence = value['sequence']
                record = value['record']
                stored = StoredRecord(canonical_bytes(record), sequence)
                if (canonical_bytes(value) != raw or self._encode(stored) != raw
                        or entry.name != self._prefix+str(sequence)+'-'+hashlib.sha256(raw).hexdigest()+'.json'):
                    raise ValueError()
                values.append(AuthoritySwitchObservation(stored,
                    StreamIdentity(self._stream_identity.created, sequence)))
        values.sort(key=lambda item: item.stored.sequence)
        if [item.stored.sequence for item in values] != list(range(1, len(values)+1)):
            raise ValueError()
        for prior, current in zip(values, values[1:]):
            before = validate_authority_switch_record(prior.stored, self._binding)['state']
            after = validate_authority_switch_record(current.stored, self._binding)['state']
            if before['switchId'] != after['switchId'] or before['source'] != after['source']:
                raise ValueError()
        return values

    def observe(self, stored):
        try:
            raw = self._encode(stored)
            name = self._prefix+str(stored.sequence)+'-'+hashlib.sha256(raw).hexdigest()+'.json'
            with self._custody() as directory:
                current = self._entries(directory)
                if stored.sequence > len(current)+1:
                    raise ValueError()
                try:
                    existing = _read(directory, name, 65_536, admit=_native_guard)
                except FileNotFoundError:
                    _publish(directory, name, raw, admit=_native_guard)
                else:
                    if existing != raw:
                        raise ValueError()
                selected = self._entries(directory)
                if selected[-1].stored.sequence < stored.sequence:
                    raise ValueError()
                os.fsync(directory)
                return selected[-1]
        except Exception:
            raise ContractError('authority_switch_observation_uncertain') from None

    def latest(self):
        try:
            with self._custody() as directory:
                values = self._entries(directory)
                return values[-1] if values else None
        except Exception:
            raise ContractError('authority_switch_observation_unavailable') from None


class AuthoritySwitchOwner:
    """Commit the barrier and issue only a current pre-cutover recovery permit."""
    def __init__(self, authority, ledger, *, host=None):
        scope = strict_loads(ledger._binding.scope) if isinstance(ledger, OwnerLedger) else {}
        if (not isinstance(authority, LedgerAuthorityReader) or not isinstance(ledger, OwnerLedger)
                or (ledger._binding.owner_domain, ledger._binding.entity_kind)
                    != ('authority-switch', 'authority-switch')
                or authority._hub != ledger._binding.hub_id
                or authority._organization != scope.get('organizationId')
                or scope.get('projectId') is not None or scope.get('workspaceId') is not None
                or host is not None and (type(host) is not AuthoritySwitchHost
                    or host._binding != ledger._binding
                    or host._stream_identity.created != ledger._identity.created)):
            raise ContractError('authority_switch_configuration')
        self._authority, self._ledger, self._host = authority, ledger, host
        self._permit_seal = object()

    def __repr__(self):
        return '<AuthoritySwitchOwner private>'

    async def _authorize(self, raw, envelope):
        authority = await self._authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(authority, raw,
            audience={'hubId': self._ledger._binding.hub_id,
                'serviceId': 'authority-switch-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.valid_until is None
                or not now < decision.valid_until
                or decision.operation != canonical_bytes(envelope['operation'])
                or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('authority_switch_access_refused')
        return decision

    async def _current(self):
        if self._host is not None:
            observed = self._host.latest()
            if observed is not None:
                self._ledger.require_recovery_identity(observed.stream_identity)
        return await self._ledger.current()

    def _retained(self, stored):
        return validate_authority_switch_record(stored, self._ledger._binding)

    def _permit(self, stored, decision, request):
        record = self._retained(stored)
        state = record['state']
        if state['phase'] != 'source-recovery-authorized':
            raise ContractError('authority_switch_recovery_refused')
        receipt = canonical_bytes({'format': 'amx-authority-switch-recovery-permit-v1',
            'decision': 'pre-cutover-abort', 'switchRef': {'id': state['switchId'],
                'ownerHubId': self._ledger._binding.hub_id, 'revision': stored.sequence},
            'recordDigest': payload_digest(record), 'source': state['source'],
            'stream': {'created': _stamp(self._ledger._identity.created),
                'minimumSequence': stored.sequence},
            'authorityRef': strict_loads(decision.authority_ref),
            'validUntil': _stamp(decision.valid_until)})
        validate('authority-switch-recovery-permit', strict_loads(receipt))
        permit = object.__new__(VerifiedLegacyRecoveryPermit)
        object.__setattr__(permit, '_seal', self._permit_seal)
        object.__setattr__(permit, '_receipt', receipt)
        object.__setattr__(permit, '_request', request)
        return permit

    async def handle(self, raw):
        if type(raw) is not bytes or len(raw) > 65_536:
            raise ContractError('authority_switch_request_invalid')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (envelope['contractId'] != 'authority-switch'
                or envelope['destinationServiceId'] != 'authority-switch-owner'
                or canonical_bytes(envelope) != raw):
            raise ContractError('authority_switch_request_invalid')
        payload, operation = envelope['payload'], envelope['operation']
        validate('authority-switch', payload)
        if (payload['switchId'] != self._ledger._binding.entity_id
                or authority_switch_id(payload['source']) != payload['switchId']):
            raise ContractError('authority_switch_binding_mismatch')
        async with asyncio.timeout(5):
            decision = await self._authorize(raw, envelope)
            current = await self._current()
            if payload['action'] == 'verify-reverse-migration':
                raise ContractError('authority_switch_reverse_incomplete')
            replay = find_outcome(current, operation['operationId'], operation['payloadDigest'])
            if replay is not None:
                self._retained(replay)
                if self._host is not None:
                    self._host.observe(replay)
                final_decision = await self._authorize(raw, envelope)
                return (self._permit(replay, final_decision, raw)
                    if payload['action'] == 'request-recovery' else replay)
            if (payload['action'] == 'request-recovery'
                    and (current.latest is None
                        or self._retained(current.latest)['state']['phase'] != 'source-fenced')):
                raise ContractError('authority_switch_recovery_refused')
            version = current.sequence + 1
            prior = None if current.latest is None else self._retained(current.latest)['state']
            transition = (None if prior is None else prior['phase'], payload['action'])
            if (operation['expectedVersion'] != current.sequence
                    or payload['action'] not in _ACTIONS
                    or transition not in {
                        (None, 'record-source-fence'),
                        ('source-fenced', 'request-recovery'),
                        ('source-fenced', 'open-target-admission'),
                        ('target-admission-open', 'fence-target')}):
                raise ContractError('authority_switch_transition_refused')
            if prior is not None and (prior['switchId'] != payload['switchId']
                    or prior['source'] != payload['source']):
                raise ContractError('authority_switch_binding_mismatch')
            state = _state_for(payload, version, prior)
            validate('authority-switch-state', state)
            record = {'schemaVersion': '1.0.0',
                'recordId': 'switch_record_'+payload_digest({'switchId': payload['switchId'],
                    'version': version, 'operationId': operation['operationId']}).split(':', 1)[1],
                'entityId': self._ledger._binding.entity_id, 'entityKind': 'authority-switch',
                'ownerHubId': self._ledger._binding.hub_id, 'ownerDomain': 'authority-switch',
                'entityVersion': version, 'previousRevision': version-1,
                'operation': operation,
                'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'outcome': 'committed', 'state': state, 'effects': [], 'artifacts': [],
                'repository': None, 'authorizationDecision': {'operationId': operation['operationId'],
                    'decision': 'allowed', 'reason': 'authorized',
                    'actorRef': operation['effectiveActorRef'], 'contractId': 'authority-switch'}}
            validate_authority_switch_record(StoredRecord(canonical_bytes(record), version),
                self._ledger._binding)
            stored = await self._ledger.append(record, expected_sequence=current.sequence,
                completion_records=0, valid_until=decision.valid_until)
            if self._host is not None:
                self._host.observe(stored)
            final_decision = await self._authorize(raw, envelope)
            return (self._permit(stored, final_decision, raw)
                if payload['action'] == 'request-recovery' else stored)

    async def validate_recovery_permit(self, permit, *, source, switch_id, stream_identity):
        """Recheck the signed recovery request and committed abort barrier before reopening.

        The future Hub caller must use this in the same recovery flow. Serialized
        receipt fields are audit data and do not grant recovery.
        """
        now = datetime.now(timezone.utc)
        if (type(permit) is not VerifiedLegacyRecoveryPermit
                or not permit._matches(self, source=source, switch_id=switch_id,
                    stream_identity=stream_identity, now=now)):
            raise ContractError('authority_switch_recovery_refused')
        current = await self._current()
        try:
            request = strict_loads(permit._request)
            await self._authorize(permit._request, request)
        except Exception:
            raise ContractError('authority_switch_recovery_refused') from None
        now = datetime.now(timezone.utc)
        if not permit._matches(self, source=source, switch_id=switch_id,
                stream_identity=stream_identity, now=now):
            raise ContractError('authority_switch_recovery_refused')
        value = permit.receipt
        if current.latest is None:
            raise ContractError('authority_switch_recovery_refused')
        record = self._retained(current.latest)
        if (record['state']['phase'] != 'source-recovery-authorized'
                or current.sequence != value['switchRef']['revision']
                or payload_digest(record) != value['recordDigest']):
            raise ContractError('authority_switch_recovery_refused')
        return True
