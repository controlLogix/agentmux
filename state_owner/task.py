"""Host-private task receiver backed by retained owner and identity records.

The caller owns transport, reply signing and request lifetime. This receiver does
not import tasks, move writer authority, publish effects or authorize execution.
"""
import asyncio
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import re
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot
from .ledger import MAX_SEQUENCE, OwnerBinding, OwnerLedger, find_outcome, validate_record


TASK_STATES = frozenset(('draft', 'ready', 'reserved', 'review_pending', 'changes_requested',
    'cancel_requested', 'cancelled', 'accepted', 'failed'))


def reservation_references(binding, operation_id):
    """Prospective business IDs for signing; neither is a committed receipt."""
    if (type(binding) is not OwnerBinding or (binding.owner_domain, binding.entity_kind) != ('task', 'task')
            or type(operation_id) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', operation_id)):
        raise ContractError('task_reservation_namespace_invalid')
    digest = payload_digest({'format': 'amx-task-reservation-reference-v1',
        'ownerHubId': binding.hub_id, 'ownerDomain': binding.owner_domain, 'taskId': binding.entity_id,
        'scope': strict_loads(binding.scope), 'operationId': operation_id}).split(':', 1)[1]
    return {name: {'id': prefix+digest, 'ownerHubId': binding.hub_id, 'revision': 1}
        for name, prefix in (('delegationRef', 'delegation_'), ('executionGrantRef', 'execution_'))}


@dataclass(frozen=True, slots=True, init=False, repr=False)
class PreparedTaskReservation:
    _owner: object
    _seal: object
    _request: bytes
    _cancellation: bytes
    _sequence: int
    _reference: bytes

    def __repr__(self):
        return '<PreparedTaskReservation uncommitted>'

    async def validate_ingress(self, reader, request_bytes, cancellation_ref):
        try:
            owner = self._owner
            if (type(owner) is not TaskOwner or self._seal is not owner._preparation_seal
                    or reader is not owner._authority or request_bytes != self._request
                    or canonical_bytes(cancellation_ref) != self._cancellation):
                raise ValueError()
        except (AttributeError, TypeError, ValueError):
            raise ContractError('task_reservation_preparation_invalid') from None
        async with asyncio.timeout(5):
            claims = owner._request(request_bytes)
            await owner._request_scope(claims)
            snapshot = await owner._ledger.current()
            replay = find_outcome(snapshot, claims['operationId'], payload_digest(claims['payload']))
            if replay is not None:
                record = owner._retained(replay)
                if (record.get('authorizationDecision', {}).get('contractId') != 'task-reserve'
                        or canonical_bytes(record['operation']['delegationRef']) != self._reference):
                    raise ContractError('task_reservation_preparation_invalid')
            else:
                if snapshot.sequence != self._sequence or snapshot.sequence != claims['expectedVersion']:
                    raise ContractError('task_reservation_preparation_stale')
                await owner._ready(snapshot, claims['payload'], claims['expiresAt'])
            return self._reference


class TaskOwner:
    def __init__(self, authority, ledger):
        if (not isinstance(authority, LedgerAuthorityReader) or not isinstance(ledger, OwnerLedger)
                or (ledger._binding.owner_domain, ledger._binding.entity_kind) != ('task', 'task')
                or authority._hub != ledger._binding.hub_id
                or authority._organization != strict_loads(ledger._binding.scope)['organizationId']):
            raise ContractError('task_owner_configuration')
        self._authority, self._ledger = authority, ledger
        self._preparation_seal = object()

    def __repr__(self):
        return '<TaskOwner private>'

    def reservation_references(self, operation_id):
        return reservation_references(self._ledger._binding, operation_id)

    async def _authorize(self, raw, envelope):
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._ledger._binding.hub_id, 'serviceId': 'task-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.valid_until is None or not now < decision.valid_until
                or decision.operation != canonical_bytes(envelope['operation'])
                or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('task_access_refused')
        return decision

    def _retained(self, stored):
        record = validate_record(stored.record, self._ledger._binding)
        state = record['state']
        if (record.get('authorizationDecision', {}).get('contractId') == 'task-import'
                or state.get('status') == 'reconciliation_required'):
            from .task_migration import validate_imported_task
            return validate_imported_task(record, self._ledger._binding, authority_id=self._authority._entity)
        if (type(state) is not dict or state.get('taskId') != self._ledger._binding.entity_id
                or type(state.get('status')) is not str or state['status'] not in TASK_STATES
                or type(state.get('assignmentEpoch')) is not int
                or not 0 <= state['assignmentEpoch'] <= MAX_SEQUENCE
                or 'reservation' not in state):
            raise ContractError('task_state_invalid')
        reservation = state['reservation']
        if reservation is not None:
            try:
                validate('task-reserve', reservation)
            except ContractError:
                raise ContractError('task_state_invalid') from None
            if (reservation['taskId'] != state['taskId']
                    or reservation['assignmentEpoch'] != state['assignmentEpoch']):
                raise ContractError('task_state_invalid')
        if state['status'] in ('reserved', 'cancel_requested') and reservation is None:
            raise ContractError('task_state_invalid')
        if record.get('authorizationDecision', {}).get('contractId') == 'task-reserve':
            embedded = state.get('delegation')
            if (reservation is None or state['status'] != 'reserved'
                    or type(embedded) is not dict or set(embedded) != {'ref', 'phase', 'offer'}):
                raise ContractError('task_state_invalid')
            grant = state.get('executionGrant')
            try:
                grant_end = datetime.fromisoformat(grant['expiresAt'])
                if not datetime.fromisoformat(record['recordedAt']) < grant_end <= datetime.fromisoformat(record['operation']['deadline']):
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise ContractError('task_execution_grant_invalid') from None
            expected = {'id': reservation['delegationId'], 'ownerHubId': self._ledger._binding.hub_id, 'revision': 1}
            offer = self._offer(state, reservation, grant['expiresAt'])
            effect = self._intent(record['operation'], offer)
            if (record['outcome'] != 'committed' or state['status'] != 'reserved'
                    or embedded != {'ref': expected, 'phase': 'offer-intent-committed', 'offer': offer}
                    or record['operation']['delegationRef'] != expected or record['effects'] != [effect]):
                raise ContractError('task_state_invalid')
            references = self.reservation_references(record['operation']['operationId'])
            if (references['delegationRef'] != expected or references['executionGrantRef'] != reservation['grantRef']
                    or reservation['grantRef'] == record['operation']['grantRef']
                    or type(grant) is not dict or not self._authority_reference(grant.get('authorityRef'))
                    or grant != self._execution_grant(record, grant['authorityRef'], grant_end)):
                raise ContractError('task_execution_grant_invalid')
        return record

    def _authority_reference(self, reference):
        return (type(reference) is dict and set(reference)=={'id', 'ownerHubId', 'revision'}
            and reference['id']==self._authority._entity and reference['ownerHubId']==self._ledger._binding.hub_id
            and type(reference['revision']) is int and 1 <= reference['revision'] <= MAX_SEQUENCE)

    def _execution_grant(self, record, authority_ref, valid_until):
        state, operation = record['state'], record['operation']
        reservation = state['reservation']
        deadline = datetime.fromisoformat(operation['deadline'])
        expires = (operation['deadline'] if deadline <= valid_until else
            valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z'))
        return {'format': 'amx-task-execution-grant-v1', 'ref': reservation['grantRef'],
            'taskId': state['taskId'], 'attemptId': reservation['attemptId'],
            'delegationRef': operation['delegationRef'], 'originHubId': self._ledger._binding.hub_id,
            'executorHubId': reservation['executorHubId'], 'scope': operation['scope'],
            'assignmentEpoch': state['assignmentEpoch'], 'repositoryRevision': reservation['repositoryRevision'],
            'taskInputRef': state['taskInputRef'], 'sourceTaskRef': {'id': self._ledger._binding.entity_id,
                'ownerHubId': self._ledger._binding.hub_id, 'revision': record['previousRevision']},
            'issuedBy': operation['effectiveActorRef'], 'requesterGrantRef': operation['grantRef'],
            'operationId': operation['operationId'], 'payloadDigest': operation['payloadDigest'],
            'issuedAt': record['recordedAt'], 'expiresAt': expires, 'authorityRef': authority_ref}

    def _request(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('task_request_limit')
        request = strict_loads(raw)
        validate('identity-ingress-request', request)
        claims = request['claims']
        if (claims['contractId'] != 'task-reserve' or claims['hubId'] != self._ledger._binding.hub_id
                or claims['profileId'] != self._authority._profile
                or claims['authorityId'] != self._authority._entity):
            raise ContractError('task_binding_mismatch')
        validate('task-reserve', claims['payload'])
        if claims['payload']['taskId'] != self._ledger._binding.entity_id:
            raise ContractError('task_binding_mismatch')
        references = self.reservation_references(claims['operationId'])
        if (claims['payload']['delegationId'] != references['delegationRef']['id']
                or claims['payload']['grantRef'] != references['executionGrantRef']
                or claims['payload']['grantRef'] == claims['grantRef']):
            raise ContractError('task_reservation_namespace_invalid')
        return claims

    async def _request_scope(self, claims):
        authority = await self._authority.current()
        grants = [grant for grant in strict_loads(authority.record)['state']['grants']
            if grant['ref'] == claims['grantRef']]
        if len(grants) != 1 or canonical_bytes(grants[0]['scope']) != self._ledger._binding.scope:
            raise ContractError('task_reservation_scope_mismatch')

    async def _ready(self, snapshot, payload, deadline):
        if snapshot.latest is None:
            raise ContractError('task_not_found')
        state = self._retained(snapshot.latest)['state']
        if state['status'] == 'reconciliation_required':
            raise ContractError('task_import_reconciliation_required')
        if state['status'] != 'ready' or state['reservation'] is not None:
            raise ContractError('task_already_reserved_or_not_ready')
        if (state.get('originHubId') != self._ledger._binding.hub_id
                or payload['grantRef']['ownerHubId'] != self._ledger._binding.hub_id
                or state['assignmentEpoch'] == MAX_SEQUENCE
                or payload['assignmentEpoch'] != state['assignmentEpoch'] + 1):
            raise ContractError('task_reservation_binding')
        # This receiver owns no later delivery attempt or receipt append. Do not
        # assume imported or unknown obligations share that zero-write bound.
        known = {'taskId', 'status', 'assignmentEpoch', 'reservation', 'originHubId', 'taskInputRef',
            'legacyId', 'parentKey', 'body', 'originPeer', 'audit', 'flags'}
        if set(state) - known or state.get('flags', {}) != {}:
            raise ContractError('task_reservation_obligations_unavailable')
        for position, stored in enumerate(snapshot.records):
            record = validate_record(stored.record, self._ledger._binding)
            if record['effects']:
                raise ContractError('task_reservation_obligations_unavailable')
            reference = record['operation']['delegationRef']
            old = record['state'].get('reservation')
            if ((reference is not None and reference['id'] == payload['delegationId']
                    and reference['ownerHubId'] == self._ledger._binding.hub_id)
                    or type(old) is dict and old.get('delegationId') == payload['delegationId']):
                raise ContractError('task_delegation_identity_reused')
            if position % 32 == 31:
                await asyncio.sleep(0)
        self._offer(state, payload, deadline)
        return state

    def _offer(self, state, payload, deadline):
        offer = {**payload, 'originHubId': self._ledger._binding.hub_id,
            'taskInputRef': state.get('taskInputRef'), 'acceptBefore': deadline}
        validate('delegation-offer', offer)
        if offer['taskInputRef']['ownerHubId'] != self._ledger._binding.hub_id:
            raise ContractError('task_reservation_binding')
        return offer

    @staticmethod
    def _intent(operation, offer):
        return {'effectId': 'offer_' + payload_digest({'operationId': operation['operationId'],
            'payloadDigest': operation['payloadDigest']}).split(':')[1],
            'contractId': 'delegation-offer', 'payloadDigest': payload_digest(offer),
            'grantRef': offer['grantRef'], 'recovery': 'query-before-retry', 'payload': offer}

    async def prepare_reservation(self, request_bytes, cancellation_ref):
        """Propose a new embedded reference; this grants no permission or receipt."""
        async with asyncio.timeout(5):
            claims = self._request(request_bytes)
            await self._request_scope(claims)
            snapshot = await self._ledger.current()
            replay = find_outcome(snapshot, claims['operationId'], payload_digest(claims['payload']))
            if replay is None:
                if snapshot.sequence != claims['expectedVersion']:
                    raise ContractError('task_reservation_preparation_stale')
                await self._ready(snapshot, claims['payload'], claims['expiresAt'])
                reference = {'id': claims['payload']['delegationId'],
                    'ownerHubId': self._ledger._binding.hub_id, 'revision': 1}
            else:
                original = self._retained(replay)
                if original.get('authorizationDecision', {}).get('contractId') != 'task-reserve':
                    raise ContractError('task_reservation_preparation_invalid')
                reference = original['operation']['delegationRef']
            result = object.__new__(PreparedTaskReservation)
            for name, value in {'_owner': self, '_seal': self._preparation_seal,
                    '_request': request_bytes, '_cancellation': canonical_bytes(cancellation_ref),
                    '_sequence': snapshot.sequence, '_reference': canonical_bytes(reference)}.items():
                object.__setattr__(result, name, value)
            return result

    async def _reserve(self, raw, envelope, prepared):
        if type(prepared) is not PreparedTaskReservation:
            raise ContractError('task_reservation_preparation_invalid')
        await self._authorize(raw, envelope)
        await prepared.validate_ingress(self._authority, getattr(prepared, '_request', None), envelope['operation']['cancellationRef'])
        if prepared._owner is not self or not self._ledger.completion_budget_required:
            raise ContractError('task_reservation_preparation_invalid')
        try:
            claims = self._request(prepared._request)
        except AttributeError:
            raise ContractError('task_reservation_preparation_invalid') from None
        operation = envelope['operation']
        if (envelope['payload'] != claims['payload'] or operation['operationId'] != claims['operationId']
                or operation['payloadDigest'] != payload_digest(claims['payload'])
                or operation['expectedVersion'] != claims['expectedVersion']
                or operation['grantRef'] != claims['grantRef']
                or operation['deadline'] != claims['expiresAt']
                or operation['approvalRefs'] != claims['approvalRefs']
                or operation['traceId'] != 'trace-' + payload_digest(claims).split(':', 1)[1]
                or operation['causationId'] != claims['operationId']
                or operation['taskId'] != claims['payload']['taskId']
                or operation['attemptId'] != claims['payload']['attemptId']
                or operation['runId'] is not None
                or envelope['correlationId'] != claims['operationId']
                or envelope['destinationHubId'] != claims['hubId']
                or envelope['ingressAttestation']['claims']['authenticatedTransportRef'] != claims['transportRef']
                or not datetime.fromisoformat(claims['issuedAt']) <= datetime.fromisoformat(
                    envelope['ingressAttestation']['claims']['issuedAt']) < datetime.fromisoformat(claims['expiresAt'])
                or datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']) > datetime.fromisoformat(claims['expiresAt'])
                or not datetime.now(timezone.utc) < datetime.fromisoformat(claims['expiresAt'])
                or canonical_bytes(operation['cancellationRef']) != prepared._cancellation
                or canonical_bytes(operation['delegationRef']) != prepared._reference):
            raise ContractError('task_reservation_preparation_invalid')
        snapshot = await self._ledger.current()
        replay = find_outcome(snapshot, operation['operationId'], operation['payloadDigest'])
        if replay is not None:
            self._retained(replay)
            await self._authorize(raw, envelope)
            return replay
        if snapshot.sequence != prepared._sequence:
            raise ContractError('task_reservation_preparation_stale')
        state = copy.deepcopy(await self._ready(snapshot, envelope['payload'], operation['deadline']))
        offer = self._offer(state, envelope['payload'], operation['deadline'])
        state.update(status='reserved', assignmentEpoch=envelope['payload']['assignmentEpoch'],
            reservation=copy.deepcopy(envelope['payload']), delegation={
                'ref': strict_loads(prepared._reference), 'phase': 'offer-intent-committed', 'offer': offer})
        prior = strict_loads(snapshot.latest.record)
        record = {**prior, 'recordId': 'task_' + uuid.uuid4().hex,
            'entityVersion': snapshot.sequence+1, 'previousRevision': snapshot.sequence,
            'operation': operation, 'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'outcome': 'committed', 'state': state, 'effects': [self._intent(operation, offer)],
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'task-reserve'}}
        decision = await self._authorize(raw, envelope)
        state['executionGrant'] = self._execution_grant(record, strict_loads(decision.authority_ref), decision.valid_until)
        offer = self._offer(state, envelope['payload'], state['executionGrant']['expiresAt'])
        state['delegation']['offer'] = offer
        record['effects'] = [self._intent(operation, offer)]
        # A lost append acknowledgment remains unknown; only the original durable
        # operation lookup on retry may reconcile it. Never issue another offer.
        stored = await self._ledger.append(record, expected_sequence=snapshot.sequence,
            valid_until=decision.valid_until, completion_records=0)
        self._retained(stored)
        await self._authorize(raw, envelope)
        return stored

    async def handle(self, raw, *, reservation_context=None):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('task_request_limit')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['contractId'] not in ('task-inspect', 'task-reserve') or envelope['kind'] != 'command':
            raise ContractError('task_contract_unavailable')
        validate(envelope['contractId'], envelope['payload'])
        if envelope['payload']['taskId'] != self._ledger._binding.entity_id:
            raise ContractError('task_binding_mismatch')
        async with asyncio.timeout(5):
            if envelope['contractId'] == 'task-reserve':
                return await self._reserve(raw, envelope, reservation_context)
            await self._authorize(raw, envelope)
            snapshot = await self._ledger.current()
            if snapshot.latest is None:
                raise ContractError('task_not_found')
            self._retained(snapshot.latest)
            # Recheck after the source await before returning any private state.
            await self._authorize(raw, envelope)
            return snapshot.latest
