"""Retain definition commands before executing their recoverable local effects.

This owner is not installed in the dashboard routes. Composition must first
complete an explicit writer handoff and pin enrolled authority, ledger, artifacts
and filesystem roots. Broker intent, artifacts and files are separate commits.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime
import re
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity import authority as identity_authority
from identity.local_browser_session import verified_local_browser_context
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import validate_record
from definition_admission import DefinitionAdmission
from definition_owner_adapter import prepare_catalog_change, _validate_catalog, catalog_head_for_worker
from definition_service import _WRITE_LOCK
from definition_effects import (INTENT_MEDIA_TYPE, capture_source, validate_intent,
                                apply_exact_source)
import ccboard
from definition_completion import EFFECT_COMMANDS, handle_effect_command, effect_progress, same_definition
from definition_budget import completion_records

# Keep catalog growth away from the shared 64 KiB record ceiling. A later
# tombstone retains the catalog plus its own bounded operation/audit/intent.
# Completion contracts must fit this reserved space before route handoff.
MAX_CATALOG_BYTES = 24 * 1024
# The envelope carries the exact operation twice, including signed claims.
MAX_OPERATION_BYTES = 32 * 1024
MAX_SAVE_RECORD_BYTES = 48 * 1024
MAX_RECORD_BYTES = 64 * 1024


def _record_capacity(record):
    saving = record['authorizationDecision']['contractId'] == 'definition-save'
    reserved_state = strict_loads(canonical_bytes(record['state']))
    if saving:
        for row in reserved_state['definitions']:
            row['effectReceiptRef'] = {'operationId': 'o' * 96, 'payloadDigest': 'sha256:' + '0' * 64}
    if ((saving and len(canonical_bytes(reserved_state)) > MAX_CATALOG_BYTES)
            or len(canonical_bytes(record['operation'])) > MAX_OPERATION_BYTES):
        raise ContractError('definition_record_headroom_required')
    limit = MAX_SAVE_RECORD_BYTES if saving else MAX_RECORD_BYTES
    if len(canonical_bytes(record)) > limit:
        raise ContractError('definition_record_headroom_required')


async def _joined(function, *args):
    worker = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        await asyncio.wait({worker})
        return worker.result()
    except asyncio.CancelledError:
        # A cancellation does not release a lock or abandon a physical mutation.
        while not worker.done():
            try:
                await asyncio.wait({worker})
            except asyncio.CancelledError:
                continue
        if not worker.cancelled():
            worker.exception()
        raise


@dataclass(frozen=True, repr=False)
class DefinitionReceipt:
    operation_id: str
    sequence: int
    definition_version: int
    replayed: bool
    file_status: str
    outcome: str = 'intent-committed'
    effect_id: str | None = None
    attempt_operation_id: str | None = None
    payload_digest: str | None = None

    def __repr__(self):
        return f'<DefinitionReceipt {self.outcome} {self.file_status}>'


class LocalDefinitionOutcomeUnconfirmed(ContractError):
    """Public recovery identity for an admitted browser operation."""
    def __init__(self, code, operation_id):
        super().__init__(code)
        self.operation_id = operation_id

    def __repr__(self):
        return f'LocalDefinitionOutcomeUnconfirmed({self.code!r})'


class DefinitionCommandOwner:
    def __init__(self, service, authority, ledger, binding, artifacts, *, writer=None):
        self._admission = DefinitionAdmission(service, authority, ledger, binding)
        if not isinstance(artifacts, OwnerArtifacts) or artifacts._owner != binding.hub_id:
            raise ContractError('definition_artifacts_configuration')
        self._service, self._authority, self._ledger = service, authority, ledger
        self._binding, self._artifacts = binding, artifacts
        self._lock = self._admission._lock
        self._writer = writer
        # Only this receiver's actual worker may create an observation. Lost
        # observations require reconciliation; file bytes cannot replace them.
        self._observations = {}
        self._target_scope = 'global' if strict_loads(binding.scope)['projectId'] is None else 'repo'

    async def activate_writer(self):
        """Host-only handoff. No route calls this or accepts a caller claim."""
        key = canonical_bytes({'hubId': self._binding.hub_id, 'domain': self._binding.owner_domain,
                               'entityId': self._binding.entity_id, 'scope': strict_loads(self._binding.scope)})
        self._writer = await _joined(self._service.claim_retained_writer, self._target_scope, key)
        return self._writer

    def __repr__(self):
        return '<DefinitionCommandOwner private>'

    async def _authorize(self, raw):
        snapshot = await self._authority.current()
        now = identity_authority._utc_now()
        decision = identity_authority.evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._binding.hub_id, 'serviceId': 'definition-owner'}, now=now)
        if decision.outcome != 'allowed' or decision.audit_actor is None or decision.operation is None:
            raise ContractError('definition_not_authorized')
        envelope = strict_loads(raw)
        operation = self._admission._operation(decision, envelope,
            contracts=('definition-save', 'definition-drop', *EFFECT_COMMANDS))
        if len(canonical_bytes(operation)) > MAX_OPERATION_BYTES:
            raise ContractError('definition_record_headroom_required')
        # Admission can change at activation or expiry without a new record.
        limits = [datetime.fromisoformat(operation['deadline']),
                  datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt'])]
        state = strict_loads(snapshot.record)['state']
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] == 'active':
                    for key in ('issuedAt', 'expiresAt'):
                        instant = datetime.fromisoformat(item[key])
                        if instant > now:
                            limits.append(instant)
        return decision, envelope, operation, min(limits)

    def _retained(self, stored, operation, envelope):
        self._admission._replay(stored, operation)
        record = validate_record(stored.record, self._binding)
        audit = record.get('authorizationDecision')
        if (record['outcome'] != 'committed' or not isinstance(audit, dict)
                or audit != {'operationId': operation['operationId'], 'decision': 'allowed',
                             'reason': 'authorized', 'actorRef': operation['effectiveActorRef'],
                             'contractId': envelope['contractId']}
                or len(record['effects']) != 1):
            raise ContractError('definition_outcome_invalid')
        effect = record['effects'][0]
        if (effect['contractId'] != envelope['contractId'] or effect['payload'] != envelope['payload']
                or effect['payloadDigest'] != operation['payloadDigest']
                or effect['grantRef'] != operation['grantRef'] or effect['recovery'] != 'query-before-retry'):
            raise ContractError('definition_outcome_invalid')
        entry = next((row for row in record['state']['definitions']
                      if row['definitionId'] == envelope['payload']['definitionId']), None)
        if (entry is None or entry['version'] != operation['expectedVersion'] + 1
                or entry['name'] != envelope['payload']['name']
                or entry['targetScope'] != envelope['payload']['scope']
                or entry['deleted'] != (envelope['contractId'] == 'definition-drop')):
            raise ContractError('definition_outcome_invalid')
        for ref in record['artifacts']:
            self._artifacts._check_ref(ref)
        return record, effect, entry

    async def _local_authority(self, context, contract, name, scope, *, resource_id=None, grant_ref=None):
        if not verified_local_browser_context(context):
            raise ContractError('local_browser_context_invalid')
        snapshot = await self._authority.current()
        now = identity_authority._utc_now()
        record = strict_loads(snapshot.record)
        state = record['state']
        index = identity_authority._indexes(state, record['ownerHubId'])
        caller_ref, bound_scope = context.caller_ref, context.scope
        authority_ref = context.authority_ref
        if (canonical_bytes(bound_scope) != self._binding.scope
                or authority_ref['id'] != record['entityId']
                or authority_ref['ownerHubId'] != record['ownerHubId']
                or authority_ref['revision'] > record['entityVersion']
                or context.authority_sequence > snapshot.sequence):
            raise ContractError('local_browser_session_changed')
        caller = index['identities'].get(identity_authority._key(caller_ref))
        if (caller is None or caller['kind'] != 'human' or not identity_authority._active(caller, now)
                or not any(identity_authority._active(item, now)
                    and item['identityRef'] == caller_ref and item['scope'] == bound_scope
                    for item in index['memberships'].values())):
            raise ContractError('definition_not_authorized')
        target = {'name': name, 'scope': scope}
        matches = [grant for grant in index['grants'].values()
            if identity_authority._active(grant, now)
            and grant['callerRef'] == caller_ref and grant['actorRef'] == caller_ref
            and grant['scope'] == bound_scope and grant['contractId'] == contract
            and grant['definitionTarget'] == target
            and (resource_id is None or grant['resourceId'] == resource_id)]
        if any(grant['decision'] == 'denied' for grant in matches):
            raise ContractError('definition_not_authorized')
        allowed = [grant for grant in matches if grant['decision'] == 'allowed'
                   and grant['delegationRef'] is None]
        if grant_ref is not None:
            allowed = [grant for grant in allowed if grant['ref'] == grant_ref]
        if len(allowed) != 1:
            raise ContractError('definition_not_authorized')
        grant = allowed[0]
        valid_until = datetime.fromisoformat(context.valid_until)
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] == 'active':
                    for key in ('issuedAt', 'expiresAt'):
                        boundary = datetime.fromisoformat(item[key])
                        if boundary > now:
                            valid_until = min(valid_until, boundary)
        if now >= valid_until:
            raise ContractError('definition_not_authorized')
        return caller, grant, valid_until

    async def execute_local_browser(self, context, target, body, *, operation_id=None):
        if target not in ('/api/board/agentdef', '/api/board/agentdrop') or not isinstance(body, dict):
            raise ContractError('local_browser_request_unavailable')
        contract = 'definition-save' if target.endswith('agentdef') else 'definition-drop'
        allowed_fields = ({'name', 'scope', 'path', 'checksum', 'description', 'cli', 'model', 'auth',
                           'persona', 'posture', 'role', 'worktree', 'tools', 'tools_deny',
                           'capabilities', 'max_instances'} if contract == 'definition-save'
                          else {'name', 'scope', 'path', 'checksum'})
        if set(body) - allowed_fields:
            raise ContractError('local_browser_request_unavailable')
        name, target_scope = body.get('name'), body.get('scope')
        if target_scope != self._target_scope:
            raise ContractError('definition_admission_scope')
        async with self._lock:
            snapshot = await self._ledger.current()
            worker_snapshot = catalog_head_for_worker(snapshot)
            entries = [] if worker_snapshot.latest is None else strict_loads(
                canonical_bytes(validate_record(worker_snapshot.latest.record, self._binding)))['state']['definitions']
            current = next((row for row in entries
                            if (row['targetScope'], row['name']) == (target_scope, name)), None)
            resource_id = None if current is None else current['definitionId']
            caller, grant, valid_until = await self._local_authority(
                context, contract, name, target_scope, resource_id=resource_id)
            definition_id = grant['resourceId'] if current is None else current['definitionId']
            expected_version = 0 if current is None else current['version']
            checksum = body.get('checksum')
            if contract == 'definition-save':
                definition = {key: body[key] for key in allowed_fields - {'name', 'scope', 'path', 'checksum'}
                              if key in body}
                payload = {'definitionId': definition_id, 'scope': target_scope, 'name': name,
                           'expectedChecksum': checksum, 'definition': definition}
            else:
                payload = {'definitionId': definition_id, 'scope': target_scope, 'name': name,
                           'expectedChecksum': checksum}
            validate(contract, payload)
            if operation_id is None:
                operation_id = 'browser_' + uuid.uuid4().hex
            elif (type(operation_id) is not str
                    or re.fullmatch(r'browser_[a-f0-9]{32}', operation_id) is None):
                raise ContractError('local_browser_request_unavailable')
            operation = {'schemaVersion': '1.0.0', 'operationId': operation_id,
                'payloadDigest': payload_digest(payload), 'expectedVersion': expected_version,
                'caller': {'principalId': caller['principalId'], 'kind': caller['kind'],
                           'authenticatedIdentityRef': caller['ref']},
                'effectiveActorRef': caller['ref'], 'scope': context.scope,
                'taskId': None, 'runId': None, 'attemptId': None, 'delegationRef': None,
                'grantRef': grant['ref'], 'approvalRefs': [], 'traceId': 'browser_' + uuid.uuid4().hex,
                'causationId': operation_id,
                'deadline': valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'cancellationRef': {'id': 'browser_' + uuid.uuid4().hex,
                                    'ownerHubId': self._binding.hub_id, 'revision': 1}}
            envelope = {'contractId': contract, 'destinationServiceId': 'definition-owner', 'payload': payload}

            async def refresh():
                current_caller, current_grant, current_until = await self._local_authority(
                    context, contract, name, target_scope,
                    resource_id=definition_id, grant_ref=grant['ref'])
                if current_caller['ref'] != caller['ref'] or current_grant['ref'] != grant['ref']:
                    raise ContractError('definition_not_authorized')
                return min(valid_until, current_until)

            try:
                return await self._execute_definition(envelope, operation, refresh,
                                                      preserve_local_operation=True)
            except ContractError as error:
                if error.code in ('owner_commit_uncertain', 'definition_outcome_unconfirmed'):
                    raise LocalDefinitionOutcomeUnconfirmed(error.code, operation_id) from None
                raise

    async def complete_local_browser(self, context, receipt):
        """Durably close the exact file observation before reporting success."""
        if not isinstance(receipt, DefinitionReceipt) or receipt.file_status != 'applied':
            raise ContractError('definition_outcome_unconfirmed')
        if receipt.payload_digest is None:
            raise ContractError('definition_outcome_unconfirmed')
        stored = await self._ledger.outcome(receipt.operation_id, receipt.payload_digest)
        if stored is None:
            raise ContractError('definition_outcome_unconfirmed')
        original = validate_record(stored.record, self._binding)
        effect = next((row for row in original['effects']
                       if row['effectId'] == receipt.effect_id), None)
        if effect is None:
            raise ContractError('definition_outcome_unconfirmed')
        target = effect['payload']
        definition_id, name, scope = target['definitionId'], target['name'], target['scope']
        original_contract = effect['contractId']
        original_grant = original['operation']['grantRef']
        caller, original_grant, original_until = await self._local_authority(context,
            original_contract, name, scope, resource_id=definition_id,
            grant_ref=original_grant)
        completion_caller, completion_grant, completion_until = await self._local_authority(
            context, 'definition-effect-complete', name, scope, resource_id=definition_id)
        if completion_caller['ref'] != caller['ref']:
            raise ContractError('definition_not_authorized')
        valid_until = min(original_until, completion_until)
        payload = {'definitionId': definition_id, 'name': name, 'scope': scope,
            'originalOperationId': original['operation']['operationId'],
            'originalPayloadDigest': original['operation']['payloadDigest'],
            'effectId': effect['effectId'],
            'attemptOperationId': receipt.attempt_operation_id}
        validate('definition-effect-complete', payload)
        operation_id = 'browser_complete_' + uuid.uuid4().hex
        operation = {'schemaVersion': '1.0.0', 'operationId': operation_id,
            'payloadDigest': payload_digest(payload), 'expectedVersion': receipt.definition_version,
            'caller': {'principalId': caller['principalId'], 'kind': caller['kind'],
                       'authenticatedIdentityRef': caller['ref']},
            'effectiveActorRef': caller['ref'], 'scope': context.scope,
            'taskId': None, 'runId': None, 'attemptId': None, 'delegationRef': None,
            'grantRef': completion_grant['ref'], 'approvalRefs': [],
            'traceId': 'browser_' + uuid.uuid4().hex,
            'causationId': original['operation']['operationId'],
            'deadline': valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'cancellationRef': {'id': 'browser_' + uuid.uuid4().hex,
                'ownerHubId': self._binding.hub_id, 'revision': 1}}
        envelope = {'contractId': 'definition-effect-complete',
            'destinationServiceId': 'definition-owner', 'payload': payload}

        async def refresh():
            current_caller, current_original, current_original_until = await self._local_authority(
                context, original_contract, name, scope,
                resource_id=definition_id, grant_ref=original_grant['ref'])
            completion_caller, current_completion, current_completion_until = await self._local_authority(
                context, 'definition-effect-complete', name, scope,
                resource_id=definition_id, grant_ref=completion_grant['ref'])
            if (current_caller['ref'] != caller['ref']
                    or current_original['ref'] != original_grant['ref']
                    or completion_caller['ref'] != caller['ref']
                    or current_completion['ref'] != completion_grant['ref']):
                raise ContractError('definition_not_authorized')
            return min(valid_until, current_original_until, current_completion_until)

        try:
            result = await handle_effect_command(self, None, envelope, operation, authorize=refresh)
        except ContractError as error:
            if error.code in ('owner_commit_uncertain', 'definition_outcome_unconfirmed'):
                raise LocalDefinitionOutcomeUnconfirmed(error.code, receipt.operation_id) from None
            raise
        if result.status != 'applied' or result.receipt_sequence is None:
            raise ContractError('definition_outcome_unconfirmed')
        return result

    async def execute(self, envelope_bytes):
        if type(envelope_bytes) is not bytes or len(envelope_bytes) > 65536:
            raise ContractError('owner_body_limit')
        async with self._lock:
            decision, envelope, operation, _ = await self._authorize(envelope_bytes)
            if envelope['contractId'] in EFFECT_COMMANDS:
                return await handle_effect_command(self, envelope_bytes, envelope, operation)
            async def refresh():
                _, current_envelope, current_operation, valid_until = await self._authorize(envelope_bytes)
                if (canonical_bytes(current_envelope) != canonical_bytes(envelope)
                        or canonical_bytes(current_operation) != canonical_bytes(operation)):
                    raise ContractError('definition_authority_changed')
                return valid_until
            return await self._execute_definition(envelope, operation, refresh)

    async def _execute_definition(self, envelope, operation, refresh, *, preserve_local_operation=False):
        if envelope['contractId'] not in ('definition-save', 'definition-drop'):
            raise ContractError('definition_command_unsupported')
        validate(envelope['contractId'], envelope['payload'])
        if (len(canonical_bytes(operation)) > MAX_OPERATION_BYTES
                or canonical_bytes(operation['scope']) != self._binding.scope):
            raise ContractError('definition_admission_scope')
        await refresh()
        await _joined(self._service.check_retained_writer, self._target_scope, self._writer)
        stored = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
        if stored is None:
            snapshot = await self._ledger.current()
            worker_snapshot = catalog_head_for_worker(snapshot)
            preparation = await _joined(prepare_catalog_change, self._service, worker_snapshot, self._binding,
                envelope['contractId'], envelope['payload'], operation['expectedVersion'])
            target, parents, source_identity = await _joined(capture_source, self._service, preparation.change.effect)
            source = preparation.change.effect.source.raw
            desired = preparation.change.effect.raw
            async def upload(data, media_type):
                await refresh()
                return await self._artifacts.upload(data, media_type=media_type)
            source_ref = None if source is None else await upload(source, 'text/markdown')
            target_ref = None if desired is None else await upload(desired, 'text/markdown')
            intent = {'format': 'amx-definition-file-intent-v1', 'operationId': operation['operationId'],
                      'payloadDigest': operation['payloadDigest'], 'definitionId': envelope['payload']['definitionId'],
                      'version': preparation.change.candidate.version, 'target': target, 'parents': parents,
                      'sourceIdentity': source_identity, 'sourceRef': source_ref, 'targetRef': target_ref}
            intent_ref = await upload(canonical_bytes(intent), INTENT_MEDIA_TYPE)
            state = preparation.candidate_state(target_ref)
            current_source = await _joined(capture_source, self._service, preparation.change.effect)
            if current_source != (target, parents, source_identity):
                raise ContractError('definition_source_changed')
            valid_until = await refresh()
            record = {'schemaVersion': '1.0.0', 'recordId': 'record-' + uuid.uuid4().hex,
                'entityId': self._binding.entity_id, 'entityKind': self._binding.entity_kind,
                'ownerHubId': self._binding.hub_id, 'ownerDomain': self._binding.owner_domain,
                'entityVersion': preparation.aggregate_version + 1, 'previousRevision': snapshot.sequence,
                'operation': operation, 'recordedAt': identity_authority._utc_now().isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'outcome': 'committed', 'state': state,
                'effects': [{'effectId': 'effect-' + uuid.uuid4().hex, 'contractId': envelope['contractId'],
                             'payloadDigest': payload_digest(envelope['payload']), 'grantRef': operation['grantRef'],
                             'recovery': 'query-before-retry', 'payload': envelope['payload']}],
                'artifacts': [ref for ref in (source_ref, target_ref, intent_ref) if ref is not None],
                'repository': None,
                'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                    'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': envelope['contractId']}}
            validate('owner-record', record)
            _record_capacity(record)
            # This value comes from the same checked catalog snapshot as the
            # conditional sequence, never from the command's claimed version.
            previous = preparation.change.previous
            target_version = 0 if previous is None else previous.version
            remaining = await completion_records(self, record, expected_sequence=snapshot.sequence)
            valid_until = await refresh()
            try:
                stored = await self._ledger.append(record, expected_sequence=snapshot.sequence,
                    expected_target_version=target_version, valid_until=valid_until,
                    admission='reconciliation' if envelope['contractId'] == 'definition-drop' else 'bulk',
                completion_records=remaining)
            except ContractError as exc:
                if exc.code != 'owner_commit_uncertain':
                    raise
                # Do not dispatch or retry append unless the original identity
                # is found in the authoritative retained history.
                try:
                    stored = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
                except ContractError:
                    raise ContractError('owner_commit_uncertain') from None
                if stored is None:
                    raise ContractError('owner_commit_uncertain') from None
        try:
            await refresh()
            record, effect, entry = self._retained(stored, operation, envelope)
            status = await self._execute_effect(None, record, effect, entry, refresh=refresh)
        except Exception as error:
            if preserve_local_operation:
                # The intent exists even when the final authority check refuses
                # the file effect. Keep its identity for query-before-retry.
                raise LocalDefinitionOutcomeUnconfirmed(
                    getattr(error, 'code', 'definition_outcome_unconfirmed'),
                    operation['operationId']) from None
            raise
        return DefinitionReceipt(operation['operationId'], stored.sequence, entry['version'], stored.replayed, status,
            effect_id=effect['effectId'], attempt_operation_id=operation['operationId'],
            payload_digest=operation['payloadDigest'])

    async def _execute_effect(self, raw, record, effect, entry, *, attempt_operation_id=None, refresh=None):
        attempt = attempt_operation_id or record['operation']['operationId']
        progress = await effect_progress(self, record, effect, entry)
        if progress.status in ('applied', 'reconciliation-required', 'superseded'):
            return progress.status
        if progress.attempt_operation_id != attempt:
            return 'superseded'
        if attempt in self._observations:
            return self._observations[attempt]['status']
        if len(self._observations) >= 128:
            return 'reconciliation-required'
        refs = [ref for ref in record['artifacts'] if ref['mediaType'] == INTENT_MEDIA_TYPE]
        if len(refs) != 1:
            raise ContractError('definition_intent_invalid')
        intent = strict_loads(await self._artifacts.retrieve(refs[0]))
        validate_intent(intent, record, effect, entry)
        source = None if intent['sourceRef'] is None else await self._artifacts.retrieve(intent['sourceRef'])
        desired = None if intent['targetRef'] is None else await self._artifacts.retrieve(intent['targetRef'])
        loop = asyncio.get_running_loop()

        async def authorize():
            if refresh is None:
                await self._authorize(raw)
            else:
                await refresh()

        async def gate():
            snapshot = await self._ledger.current()
            if snapshot.latest is None:
                raise ContractError('owner_history_gap')
            state = strict_loads(snapshot.latest.record)['state']
            _validate_catalog(state)
            if canonical_bytes(state['scope']) != self._binding.scope:
                raise ContractError('definition_admission_scope')
            current = next((row for row in state['definitions'] if row['definitionId'] == entry['definitionId']), None)
            progress = await effect_progress(self, record, effect, entry, snapshot=snapshot)
            await authorize()
            return (same_definition(current, entry) and progress.attempt_operation_id == attempt
                    and progress.status in ('pending', 'retry-authorized'))

        def observed(status):
            self._observations[attempt] = {'definitionId': entry['definitionId'],
                'originalOperationId': record['operation']['operationId'],
                'originalPayloadDigest': record['operation']['payloadDigest'], 'effectId': effect['effectId'],
                'attemptOperationId': attempt, 'definitionVersion': entry['version'], 'status': status,
                'observedAt': identity_authority._utc_now().isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            return status

        def apply():
            with _WRITE_LOCK:
                def before_commit():
                    if not asyncio.run_coroutine_threadsafe(gate(), loop).result():
                        raise ContractError('definition_effect_superseded')
                # The worker owns the file lock while the original event loop
                # performs bounded authoritative reads. Cancellation joins both.
                if not asyncio.run_coroutine_threadsafe(gate(), loop).result():
                    return observed('superseded')
                body = effect['payload']
                legacy = {**body.get('definition', {}), 'name': body['name'], 'scope': body['scope'],
                          'checksum': body['expectedChecksum']}
                try:
                    prepared = self._service._preflight_locked(effect['contractId'].removeprefix('definition-'), legacy)
                    if prepared.source.raw != source or prepared.raw != desired:
                        return observed('reconciliation-required')
                    if not asyncio.run_coroutine_threadsafe(gate(), loop).result():
                        return observed('superseded')
                    apply_exact_source(self._service, prepared, intent, before_commit, self._writer)
                except (ccboard.Invalid, ccboard.Refused, ccboard.NotFound, OSError):
                    return observed('reconciliation-required')
                except ContractError as exc:
                    if exc.code == 'definition_effect_superseded':
                        return observed('superseded')
                    if exc.code not in ('definition_file_reconciliation_required', 'definition_root_unavailable',
                                        'definition_target_redirected'):
                        raise
                    return observed('reconciliation-required')
                # Publish the private observation before releasing the file lock.
                # A concurrent completion can then close this exact attempt.
                return observed('applied')

        return await _joined(apply)
