"""Retained ordinary Secret.Use intent, dispatch and outcome authority."""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import threading

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot, _active, _indexes, _key
from identity.ingress import EnrolledIngress
from identity.ordinary_secret import OrdinarySecretAuthority, validate_enrollment
from native_security.secret_custody import _admit, _open_namespace, _open_root, _read_file
from native_security.descriptor_admission import DescriptorPurpose
from state_owner.ledger import OwnerLedger, StoredRecord, validate_record
from .secret_consumer import AtlassianAccountCheckEnrollment, SecretConsumerObservation

PHASE_CONTRACTS = frozenset(('ordinary-secret-dispatch', 'ordinary-secret-complete'))
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


def _fail(code='ordinary_secret_journal_invalid'):
    raise ContractError(code) from None


def _reference(identifier, hub, revision):
    return {'id': identifier, 'ownerHubId': hub, 'revision': revision}


def _valid_ref(value):
    try:
        return (type(value) is dict and set(value) == {'id', 'ownerHubId', 'revision'}
            and all(type(value[k]) is str and _ID.fullmatch(value[k]) for k in ('id', 'ownerHubId'))
            and type(value['revision']) is int and 0 <= value['revision'] <= 9007199254740991)
    except Exception:
        return False


def secret_use_identity(scope, operation_id):
    if type(operation_id) is not str or not _ID.fullmatch(operation_id):
        _fail()
    return 'secret-use-' + hashlib.sha256(canonical_bytes({
        'scope': scope, 'originalOperationId': operation_id})).hexdigest()


def enrollment_digest(enrollment):
    if type(enrollment) is not AtlassianAccountCheckEnrollment:
        _fail()
    return payload_digest({'record': strict_loads(enrollment.record),
        'destination': enrollment.base_url, 'deployment': enrollment.deployment,
        'email': enrollment.email, 'expectedAccount': enrollment.expected_account,
        'trustDigest': 'sha256:' + hashlib.sha256(enrollment.trust_pem).hexdigest()})


def _same_original(left, right):
    return canonical_bytes(left) == canonical_bytes(right)


@dataclass(frozen=True, slots=True, repr=False)
class SecretJournalTransition:
    stored: StoredRecord
    acknowledged: bool
    replayed: bool


class _PrivateObservations:
    """Immutable physical evidence; it cannot authorize an effect or receipt."""
    def __init__(self, root):
        self._root = Path(root)
        self._fd = _open_root(self._root)
        try:
            self._identity = self._identity_of(self._fd)
        except BaseException:
            os.close(self._fd)
            raise
        self._busy = threading.Lock()

    @staticmethod
    def _identity_of(fd):
        value = os.fstat(fd)
        return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid

    def _check(self):
        if self._fd is None:
            _fail('ordinary_secret_observation_closed')
        _admit(self._fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        current = _open_root(self._root)
        try:
            if self._identity_of(current) != self._identity:
                _fail('ordinary_secret_observation_changed')
        finally:
            os.close(current)

    def access(self, binding, dispatch, *, evidence=None):
        if not self._busy.acquire(blocking=False):
            _fail('ordinary_secret_observation_busy')
        try:
            return self._access(binding, dispatch, evidence=evidence)
        finally:
            self._busy.release()

    def _access(self, binding, dispatch, *, evidence):
        self._check()
        if not _valid_ref(dispatch) or dispatch['ownerHubId'] != binding.hub_id:
            _fail()
        descriptors, locked = [], False
        try:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except BlockingIOError:
                _fail('ordinary_secret_observation_busy')
            directory = self._fd
            for part in ('ordinary-secret-observations', binding.hub_id, binding.entity_id):
                directory = _open_namespace(directory, part, create=evidence is not None)
                descriptors.append(directory)
            name = dispatch['id'] + '.observation'
            if evidence is not None:
                raw = canonical_bytes(evidence)
                if len(raw) > 8192:
                    _fail()
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW, 0o600, dir_fd=directory)
                except FileExistsError:
                    pass
                else:
                    try:
                        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
                        offset = 0
                        while offset < len(raw):
                            count = os.write(fd, raw[offset:])
                            if count <= 0:
                                _fail('ordinary_secret_observation_write_uncertain')
                            offset += count
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                retained = _read_file(directory, name)
                if retained != raw:
                    _fail('ordinary_secret_observation_recovery_required')
            else:
                retained = _read_file(directory, name)
            if len(retained) > 8192:
                _fail()
            self._check()
            return retained
        except FileNotFoundError:
            if evidence is not None:
                _fail('ordinary_secret_observation_write_uncertain')
            return None
        except ContractError:
            raise
        except Exception:
            _fail('ordinary_secret_observation_unavailable')
        finally:
            for fd in reversed(descriptors):
                os.close(fd)
            if locked:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    def close(self):
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)


class SecretOperationJournal:
    def __init__(self, ledger, reader, *, enrollment, observation_root):
        if (type(reader) is not LedgerAuthorityReader or not isinstance(ledger, OwnerLedger)
                or not ledger.completion_budget_required
                or (ledger._binding.owner_domain, ledger._binding.entity_kind)
                    != ('ordinary-secret-uses', 'effect')
                or ledger._binding.hub_id != reader._hub):
            _fail('ordinary_secret_journal_configuration')
        self._enrollment = enrollment
        self._digest = enrollment_digest(enrollment)
        record = strict_loads(enrollment.record)
        scope = strict_loads(ledger._binding.scope)
        if (record['ref'] != record['generationRef'] or record['ref']['revision'] != 1
                or record['ref']['ownerHubId'] != reader._hub
                or record['profileId'] != reader._profile
                or record['scope']['organizationId'] != scope['organizationId']
                or record['scope']['projectId'] != scope['projectId']
                or record['scope']['workspaceId'] not in (None, scope['workspaceId'])):
            _fail('ordinary_secret_journal_configuration')
        self._record, self._owner = record, canonical_bytes(record['ownerIdentityRef'])
        self._ledger, self._reader, self._binding = ledger, reader, ledger._binding
        self._authority = OrdinarySecretAuthority(reader)
        self._lock = asyncio.Lock()
        self._observations = _PrivateObservations(observation_root)
        self._disk_tasks, self._closed = set(), False

    def __repr__(self):
        return '<SecretOperationJournal private>'

    def ref(self, stored):
        return _reference(strict_loads(stored.record)['recordId'], self._binding.hub_id, stored.sequence)

    async def authorize(self, resolve_envelope, *, native_proof=None):
        result = await self._authority.resolve(resolve_envelope, native_proof=native_proof)
        operation = strict_loads(result.original_operation)
        if (result.record != self._enrollment.record or result.scope != self._binding.scope
                or secret_use_identity(strict_loads(result.scope), operation['operationId'])
                    != self._binding.entity_id):
            _fail('ordinary_secret_journal_access_refused')
        return result

    async def authorize_query(self, raw, group=None, *, native_proof=None):
        """Authorize a new read without renewing its historical effect proof."""
        if type(raw) is not bytes or len(raw) > 65536:
            _fail('ordinary_secret_query_refused')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (canonical_bytes(envelope) != raw or envelope['contractId'] != 'capability-outcome-query'
                or envelope['destinationHubId'] != self._binding.hub_id
                or envelope['destinationServiceId'] != 'outcome-owner'):
            _fail('ordinary_secret_query_refused')
        payload, operation = envelope['payload'], envelope['operation']
        validate('capability-outcome-query', payload)
        original = payload['input']
        if (original['contractId'] != 'capability-secret-use'
                or operation['operationId'] == original['operationId']
                or canonical_bytes(operation['scope']) != self._binding.scope
                or payload['resourceRef'] != self._record['generationRef']
                or operation['effectiveActorRef'] != self._record['callerIdentityRef']
                or secret_use_identity(operation['scope'], original['operationId']) != self._binding.entity_id):
            _fail('ordinary_secret_query_refused')
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw, audience={
            'hubId': self._binding.hub_id, 'serviceId': 'outcome-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                or decision.valid_until is None or now >= decision.valid_until):
            _fail('ordinary_secret_query_refused')
        if native_proof is not None:
            from identity.ordinary_secret import refresh_secret_query_authority
            snapshot, now = await refresh_secret_query_authority(native_proof, self._reader, snapshot, raw,
                now=now, valid_until=decision.valid_until)
        current = strict_loads(snapshot.record)
        index = _indexes(current['state'], self._binding.hub_id)
        item = index['ordinarySecretReferences'].get(_key(payload['resourceRef']))
        if item is None or canonical_bytes(item) != self._enrollment.record or not _active(item, now):
            _fail('ordinary_secret_query_refused')
        validate_enrollment(current['state'], index, item, self._binding.hub_id)
        if group is not None:
            retained = group['original']
            actual = retained['operation']
            if (retained['contractId'] != original['contractId']
                    or actual['operationId'] != original['operationId']
                    or actual['payloadDigest'] != original['payloadDigest']
                    or actual['caller']['authenticatedIdentityRef'] != operation['caller']['authenticatedIdentityRef']
                    or actual['effectiveActorRef'] != operation['effectiveActorRef']
                    or actual['scope'] != operation['scope']
                    or retained['payload'] != {'resourceRef': item['generationRef'], 'input': {
                        'consumerRef': item['consumerRef'], 'purposeRef': item['purposeRef']}}
                    or group['state']['enrollmentDigest'] != self._digest):
                _fail('ordinary_secret_query_refused')
        return envelope

    def _record_for(self, snapshot, envelope, state, identifier):
        operation = envelope['operation']
        return {'schemaVersion': '1.0.0', 'recordId': identifier,
            'entityId': self._binding.entity_id, 'entityKind': self._binding.entity_kind,
            'ownerHubId': self._binding.hub_id, 'ownerDomain': self._binding.owner_domain,
            'entityVersion': snapshot.sequence + 1, 'previousRevision': snapshot.sequence,
            'operation': operation, 'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'outcome': 'committed', 'state': state, 'effects': [], 'artifacts': [], 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': operation['effectiveActorRef'],
                'contractId': envelope['contractId']}}

    def _read(self, snapshot):
        group = None
        required = {'format', 'original', 'originalRequestDigest', 'enrollmentDigest',
            'resourceRef', 'claimRef', 'dispatchRef', 'phase', 'outcome', 'phaseEnvelope'}
        for stored in snapshot.records:
            record = validate_record(stored.record, self._binding)
            state = record['state']
            if (type(state) is not dict or set(state) != required
                    or state['format'] != 'agentmux-ordinary-secret-use-v1'
                    or state['enrollmentDigest'] != self._digest
                    or state['resourceRef'] != self._record['generationRef']):
                _fail()
            original = state['original']
            validate('message-envelope', original)
            operation = original['operation']
            if (original['contractId'] != 'capability-secret-use'
                    or original['destinationHubId'] != self._binding.hub_id
                    or original['destinationServiceId'] != 'secret-owner'
                    or canonical_bytes(operation['scope']) != self._binding.scope
                    or original['payload'] != {'resourceRef': self._record['ref'], 'input': {
                        'consumerRef': self._record['consumerRef'], 'purposeRef': self._record['purposeRef']}}
                    or payload_digest(original['payload']) != operation['payloadDigest']
                    or payload_digest(original) != state['originalRequestDigest']
                    or operation['expectedVersion'] != 1
                    or operation['effectiveActorRef'] != self._record['callerIdentityRef']
                    or secret_use_identity(operation['scope'], operation['operationId']) != self._binding.entity_id):
                _fail()
            if group is None:
                if (state['phase'] != 'prepared' or state['phaseEnvelope'] is not None
                        or state['outcome'] is not None or state['dispatchRef'] is not None
                        or state['claimRef'] != self.ref(stored) or record['operation'] != operation):
                    _fail()
                group = {'original': original, 'claim': stored, 'latest': stored, 'state': state}
                continue
            before = group['state']
            if any(state[key] != before[key] for key in required - {
                    'phase', 'phaseEnvelope', 'dispatchRef', 'outcome'}):
                _fail()
            phase = state['phaseEnvelope']
            validate('message-envelope', phase)
            if phase['contractId'] not in PHASE_CONTRACTS:
                _fail()
            validate(phase['contractId'], phase['payload'])
            phase_op, body = phase['operation'], phase['payload']
            if (record['operation'] != phase_op
                    or phase_op['operationId'] == operation['operationId']
                    or phase_op['caller']['kind'] != 'service'
                    or canonical_bytes(phase_op['caller']['authenticatedIdentityRef']) != self._owner
                    or canonical_bytes(phase_op['effectiveActorRef']) != self._owner
                    or phase['destinationHubId'] != self._binding.hub_id
                    or phase['destinationServiceId'] != 'secret-owner'
                    or payload_digest(body) != phase_op['payloadDigest']
                    or phase_op['expectedVersion'] != group['latest'].sequence
                    or body['resourceRef'] != state['resourceRef']
                    or body['journalRef'] != _reference(self._binding.entity_id,
                        self._binding.hub_id, group['latest'].sequence)
                    or body['claimRef'] != state['claimRef']
                    or body['originalOperationId'] != operation['operationId']
                    or body['originalPayloadDigest'] != operation['payloadDigest']
                    or body['enrollmentDigest'] != self._digest):
                _fail()
            if phase['contractId'] == 'ordinary-secret-dispatch':
                if (before['phase'] != 'prepared' or state['phase'] != 'dispatching'
                        or state['outcome'] is not None or state['dispatchRef'] != self.ref(stored)):
                    _fail()
            elif (before['phase'] != 'dispatching' or state['phase'] != 'finished'
                    or state['dispatchRef'] != before['dispatchRef']
                    or state['outcome'] not in ('accepted', 'rejected', 'uncertain')):
                _fail()
            group = {**group, 'latest': stored, 'state': state}
        return group

    async def current(self):
        return self._read(await self._ledger.current())

    async def _append(self, record, snapshot, *, valid_until, target_version=None, remaining):
        try:
            stored = await self._ledger.append(record, expected_sequence=snapshot.sequence,
                valid_until=valid_until, expected_target_version=target_version,
                completion_records=remaining)
            acknowledged = stored.record == canonical_bytes(record)
            return SecretJournalTransition(stored, acknowledged, not acknowledged)
        except ContractError as error:
            if error.code not in ('owner_commit_uncertain', 'owner_revision_conflict'):
                raise
            # A retained original proves state, never receipt of the original ACK.
            retained = await self._ledger.outcome(record['operation']['operationId'],
                                                   record['operation']['payloadDigest'])
            if retained is None:
                _fail('ordinary_secret_outcome_uncertain')
            return SecretJournalTransition(retained, False, True)

    async def prepare(self, resolve_envelope, *, native_proof=None):
        async with self._lock:
            resolution = await self.authorize(resolve_envelope, native_proof=native_proof)
            original = strict_loads(resolve_envelope)['payload']['originalEnvelope']
            snapshot = await self._ledger.current()
            group = self._read(snapshot)
            if group is not None:
                if not _same_original(group['original'], original):
                    _fail('ordinary_secret_original_conflict')
                return SecretJournalTransition(group['latest'], False, True)
            # A unique candidate record distinguishes this instance's actual ACK
            # from OwnerLedger returning another instance's retained original.
            identifier = 'secret-intent-' + secrets.token_hex(24)
            state = {'format': 'agentmux-ordinary-secret-use-v1', 'original': original,
                'originalRequestDigest': resolution.original_request_digest,
                'enrollmentDigest': self._digest, 'resourceRef': self._record['generationRef'],
                'claimRef': _reference(identifier, self._binding.hub_id, 1),
                'dispatchRef': None, 'phase': 'prepared', 'outcome': None, 'phaseEnvelope': None}
            record = self._record_for(snapshot, original, state, identifier)
            await self.authorize(resolve_envelope, native_proof=native_proof)
            return await self._append(record, snapshot, valid_until=resolution.valid_until,
                target_version=1, remaining=2)

    async def _authorize_phase(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            _fail()
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['contractId'] not in PHASE_CONTRACTS:
            _fail()
        validate(envelope['contractId'], envelope['payload'])
        decision = await self._reader.evaluate(raw, audience={
            'hubId': self._binding.hub_id, 'serviceId': 'secret-owner'})
        operation = envelope['operation']
        if (decision.outcome != 'allowed' or decision.valid_until is None
                or decision.valid_until <= datetime.now(timezone.utc)
                or canonical_bytes(operation['scope']) != self._binding.scope
                or operation['caller']['kind'] != 'service'
                or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._owner
                or canonical_bytes(operation['effectiveActorRef']) != self._owner):
            _fail('ordinary_secret_phase_access_refused')
        return envelope, decision

    def phase_payload(self, group):
        original = group['original']['operation']
        return {'resourceRef': self._record['generationRef'],
            'journalRef': _reference(self._binding.entity_id, self._binding.hub_id, group['latest'].sequence),
            'claimRef': group['state']['claimRef'], 'originalOperationId': original['operationId'],
            'originalPayloadDigest': original['payloadDigest'], 'enrollmentDigest': self._digest}

    async def advance(self, raw):
        async with self._lock:
            envelope, decision = await self._authorize_phase(raw)
            snapshot = await self._ledger.current()
            group = self._read(snapshot)
            if group is None:
                _fail()
            operation, body = envelope['operation'], envelope['payload']
            existing = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if existing is not None:
                retained = strict_loads(existing.record)['state']['phaseEnvelope']
                if not _same_original(retained, envelope):
                    _fail('ordinary_secret_original_conflict')
                return SecretJournalTransition(existing, False, True)
            expected = self.phase_payload(group)
            if (any(body.get(key) != value for key, value in expected.items())
                    or operation['operationId'] == group['original']['operation']['operationId']
                    or operation['expectedVersion'] != snapshot.sequence):
                _fail('ordinary_secret_phase_binding_refused')
            state = strict_loads(canonical_bytes(group['state']))
            identifier = 'secret-phase-' + secrets.token_hex(24)
            if envelope['contractId'] == 'ordinary-secret-dispatch':
                if state['phase'] != 'prepared':
                    _fail('ordinary_secret_phase_binding_refused')
                state.update(phase='dispatching', dispatchRef=_reference(identifier,
                    self._binding.hub_id, snapshot.sequence + 1))
            else:
                if state['phase'] != 'dispatching':
                    _fail('ordinary_secret_phase_binding_refused')
                observed = await self.load_observation(group)
                if observed is None or body['observationId'] != self.observation_identity(group, observed):
                    _fail('ordinary_secret_observation_required')
                state.update(phase='finished', outcome=observed.status)
            state['phaseEnvelope'] = envelope
            record = self._record_for(snapshot, envelope, state, identifier)
            self._read(type(snapshot)((*snapshot.records, StoredRecord(canonical_bytes(record),
                        snapshot.sequence + 1)), snapshot.sequence + 1))
            _, final = await self._authorize_phase(raw)
            return await self._append(record, snapshot, valid_until=min(decision.valid_until, final.valid_until),
                remaining=1 if state['phase'] == 'dispatching' else 0)

    def _evidence(self, group, observed):
        if type(observed) is not SecretConsumerObservation or group['state']['dispatchRef'] is None:
            _fail('ordinary_secret_observation_required')
        operation = group['original']['operation']
        return {'format': 'agentmux-ordinary-secret-observation-v1',
            'originalOperationId': operation['operationId'], 'originalPayloadDigest': operation['payloadDigest'],
            'originalRequestDigest': group['state']['originalRequestDigest'],
            'dispatchRef': group['state']['dispatchRef'], 'enrollmentDigest': self._digest,
            'status': observed.status, 'reason': observed.reason}

    def observation_identity(self, group, observed):
        return 'secret-observation-' + hashlib.sha256(canonical_bytes(self._evidence(group, observed))).hexdigest()

    async def save_observation(self, group, observed):
        evidence = self._evidence(group, observed)
        retained = await self._disk(group['state']['dispatchRef'], evidence=evidence)
        if retained != canonical_bytes(evidence):
            _fail('ordinary_secret_observation_write_uncertain')
        return self.observation_identity(group, observed)

    async def load_observation(self, group):
        if group['state']['dispatchRef'] is None:
            return None
        raw = await self._disk(group['state']['dispatchRef'])
        if raw is None:
            return None
        try:
            value = strict_loads(raw)
            observed = SecretConsumerObservation(value['status'], value['reason'])
            if raw != canonical_bytes(self._evidence(group, observed)):
                _fail()
            return observed
        except Exception:
            _fail('ordinary_secret_observation_changed')

    async def _disk(self, dispatch, *, evidence=None):
        if self._closed:
            _fail('ordinary_secret_observation_closed')
        task = asyncio.create_task(asyncio.to_thread(self._observations.access,
            self._binding, dispatch, evidence=evidence))
        self._disk_tasks.add(task)
        def done(original):
            self._disk_tasks.discard(original)
            if not original.cancelled():
                original.exception()
        task.add_done_callback(done)
        await asyncio.wait((task,))
        return task.result()

    async def close(self):
        self._closed = True
        if self._disk_tasks:
            await asyncio.gather(*tuple(self._disk_tasks), return_exceptions=True)
        self._observations.close()


class SecretPhaseSigner:
    def __init__(self, journal, ingress, *, transport_ref, grants, signing_seed):
        if (type(journal) is not SecretOperationJournal or type(ingress) is not EnrolledIngress
                or ingress._reader is not journal._reader or not _valid_ref(transport_ref)
                or type(grants) is not dict or set(grants) != PHASE_CONTRACTS
                or any(not _valid_ref(value) for value in grants.values())
                or any(value['ownerHubId'] != journal._binding.hub_id for value in (transport_ref, *grants.values()))
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            _fail('ordinary_secret_phase_configuration')
        self._journal, self._ingress = journal, ingress
        self._transport, self._grants, self._seed = canonical_bytes(transport_ref), canonical_bytes(grants), signing_seed

    def __repr__(self):
        return '<SecretPhaseSigner private>'

    async def admit(self, contract, group, *, observation_id=None):
        if contract not in PHASE_CONTRACTS:
            _fail()
        payload = self._journal.phase_payload(group)
        if observation_id is not None:
            payload['observationId'] = observation_id
        validate(contract, payload)
        reader, now = self._journal._reader, datetime.now(timezone.utc)
        stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': reader._hub,
            'profileId': reader._profile, 'authorityId': reader._entity,
            'transportRef': strict_loads(self._transport), 'grantRef': strict_loads(self._grants)[contract],
            'operationId': 'secret-owner-' + secrets.token_hex(24), 'expectedVersion': group['latest'].sequence,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now + timedelta(seconds=5))}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
                                   'signature': sign_claims(claims, self._seed)})
        admitted = await self._ingress.admit(request,
            cancellation_ref=group['original']['operation']['cancellationRef'])
        if admitted.decision.outcome != 'allowed' or admitted.envelope is None:
            _fail('ordinary_secret_phase_access_refused')
        await self._journal._authorize_phase(admitted.envelope)
        return admitted.envelope
