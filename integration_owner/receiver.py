"""Receive signed effect commands through actual authority and durable owner APIs.

No production subscription or dashboard route is installed here. Canonical
contracts and current authority are required. An enrolled Atlassian worker can
dispatch after a separate signed attempt claim; intent alone never dispatches.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import AuthorityReader
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject, validate_record
from state_owner.artifacts import OwnerArtifacts
from .intent import effect_id, intent, query, reference, retained_state
from .credentials import AtlassianCredentialResolver
from .github_worker import GithubCredentialResolver, GithubWorker
from .workers import AtlassianWorker


@dataclass(frozen=True, repr=False)
class IntegrationReply:
    operation_id: str
    original_operation_id: str
    original_payload_digest: str
    sequence: int
    status: str
    attempt_operation_id: str | None = None

    def __repr__(self):
        return '<IntegrationReply private; no external result>'

    def wire_payload(self):
        value = {'operationId': self.operation_id, 'originalOperationId': self.original_operation_id,
            'originalPayloadDigest': self.original_payload_digest, 'sequence': self.sequence,
            'attemptOperationId': self.attempt_operation_id, 'phase': self.status}
        validate('integration-effect-reply', value)
        return value


class IntegrationOwner:
    def __init__(self, authority, ledger, binding, *, provider, credential_ref, artifacts=None, credentials=None):
        if (not isinstance(authority, AuthorityReader) or not isinstance(ledger, OwnerLedger)
                or not isinstance(binding, OwnerBinding) or binding.entity_kind != 'effect'
                or binding.owner_domain != 'integrations' or ledger._binding != binding
                or not ledger.completion_budget_required
                or authority._hub != binding.hub_id
                or authority._organization != strict_loads(binding.scope)['organizationId']
                or ledger._subject != owner_subject(binding)
                or strict_loads(binding.scope)['projectId'] is None or provider not in ('github', 'jira', 'confluence')
                or (artifacts is not None and (not isinstance(artifacts, OwnerArtifacts)
                                              or artifacts._owner != binding.hub_id))):
            raise ContractError('integration_owner_configuration')
        credential = strict_loads(canonical_bytes(credential_ref))
        reference(credential)
        if credential['ownerHubId'] != binding.hub_id:
            raise ContractError('integration_owner_configuration')
        self._authority, self._ledger, self._binding = authority, ledger, binding
        self._credential, self._artifacts = canonical_bytes(credential), artifacts
        self._provider = provider
        self._lock = asyncio.Lock()
        if credentials is None:
            self._worker = None
        elif provider == 'github':
            if (type(credentials) is not GithubCredentialResolver
                    or credentials._binding[0] != self._credential):
                raise ContractError('integration_owner_configuration')
            self._worker = GithubWorker(credentials)
        else:
            if (type(credentials) is not AtlassianCredentialResolver
                    or credentials._binding[0] != self._credential or credentials._binding[1] != provider):
                raise ContractError('integration_owner_configuration')
            self._worker = AtlassianWorker(credentials)
        self._observations = {}
        self._closed = False

    def __repr__(self):
        return '<IntegrationOwner private>'

    async def _authorize(self, raw, envelope):
        if self._closed:
            raise ContractError('integration_owner_closed')
        operation = envelope['operation']
        decision = await self._authority.evaluate(raw, audience={
            'hubId': self._binding.hub_id, 'serviceId': 'integration-owner'})
        if (self._closed or decision.outcome != 'allowed' or decision.audit_actor is None
                or decision.operation != canonical_bytes(operation)
                or decision.valid_until is None or decision.valid_until <= datetime.now(timezone.utc)
                or canonical_bytes(operation['scope']) != self._binding.scope):
            raise ContractError('integration_access_refused')
        if envelope['contractId'] in ('integration-intent', 'integration-attempt-start') and not operation['approvalRefs']:
            raise ContractError('integration_approval_required')
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError()
        return decision

    async def close(self, *, timeout=5.0):
        self._closed = True
        if self._worker is not None:
            await self._worker.close(timeout=timeout)

    def _reply(self, operation_id, state, sequence):
        return IntegrationReply(operation_id, state['originalOperationId'], state['originalPayloadDigest'],
            sequence, state['phase'], None if 'attempt' not in state else state['attempt']['operationId'])

    def _binding_check(self, body, operation, contract):
        ref = body['effectRef']
        original = operation['operationId'] if contract == 'integration-intent' else body['originalOperationId']
        if (ref['id'] != self._binding.entity_id or ref['ownerHubId'] != self._binding.hub_id
                or ref['id'] != effect_id(operation['scope'], original)
                or ref['revision'] != operation['expectedVersion']):
            raise ContractError('integration_access_refused')

    def _retained(self, stored):
        record = validate_record(stored.record, self._binding)
        state = retained_state(record)
        if (canonical_bytes(state['intent']['credentialRef']) != self._credential
                or state['intent']['action'].split('-', 1)[0] != self._provider
                or state['intent']['effectRef'] != {
                    'id': self._binding.entity_id, 'ownerHubId': self._binding.hub_id, 'revision': 0}):
            raise ContractError('integration_retained_intent_invalid')
        return state

    async def handle(self, raw):
        try:
            return await self._handle(raw)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            if error.code == 'owner_operation_conflict':
                raise ContractError('integration_original_identity_conflict') from None
            if error.code in {'integration_access_refused', 'integration_approval_required',
                    'integration_reconciliation_required', 'integration_original_identity_conflict',
                    'integration_revision_conflict', 'integration_effect_already_bound'}:
                raise
            raise ContractError('integration_request_refused') from None
        except Exception:
            # SDK, broker and caller data never become public diagnostic text.
            raise ContractError('integration_request_refused') from None

    async def _handle(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('integration_body_limit')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        contract = envelope['contractId']
        lifecycle = ('integration-attempt-start', 'integration-attempt-complete', 'integration-effect-reconcile')
        if contract not in ('integration-intent', 'integration-effect-query', *lifecycle):
            raise ContractError('integration_contract_unsupported')
        # This also requires canonical registration; local validators alone can
        # never enable an unregistered command or weaken the actual authority.
        validate(contract, envelope['payload'])
        if contract in lifecycle:
            body = strict_loads(canonical_bytes(envelope['payload']))
        else:
            body = intent(envelope['payload']) if contract == 'integration-intent' else query(envelope['payload'])
        operation = envelope['operation']
        self._binding_check(body, operation, contract)
        if contract == 'integration-effect-query' and operation['operationId'] == body['originalOperationId']:
            raise ContractError('integration_original_identity_conflict')
        async with self._lock:
            await self._authorize(raw, envelope)
            if contract in lifecycle:
                from .commands import handle_lifecycle
                return await handle_lifecycle(self, raw, envelope, body)
            if contract == 'integration-effect-query':
                snapshot = await self._ledger.current()
                if snapshot.sequence != body['effectRef']['revision']:
                    raise ContractError('integration_revision_conflict')
                stored = snapshot.latest
                if stored is None:
                    status, sequence = 'absent', 0
                else:
                    from .lifecycle import read_lifecycle
                    view = read_lifecycle(snapshot, self._binding)
                    self._retained(view.original)
                    state = strict_loads(view.state)
                    if (state['originalOperationId'] != body['originalOperationId']
                            or state['originalPayloadDigest'] != body['originalPayloadDigest']):
                        raise ContractError('integration_original_identity_conflict')
                    await self._authorize(raw, envelope)
                    return self._reply(operation['operationId'], state, snapshot.sequence)
                await self._authorize(raw, envelope)
                return IntegrationReply(operation['operationId'], body['originalOperationId'],
                                        body['originalPayloadDigest'], sequence, status)
            if (canonical_bytes(body['credentialRef']) != self._credential
                    or body['action'].split('-', 1)[0] != self._provider
                    or operation['expectedVersion'] != 0):
                raise ContractError('integration_access_refused')
            content = body['contentRef']
            if content is not None:
                if self._artifacts is None:
                    raise ContractError('integration_artifact_unavailable')
                self._artifacts._check_ref(content)
            stored = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if stored is None:
                snapshot = await self._ledger.current()
                if snapshot.sequence != 0:
                    raise ContractError('integration_effect_already_bound')
                decision = await self._authorize(raw, envelope)
                record = {'schemaVersion': '1.0.0', 'recordId': 'i' + uuid.uuid4().hex,
                    'entityId': self._binding.entity_id, 'entityKind': 'effect',
                    'ownerHubId': self._binding.hub_id, 'ownerDomain': 'integrations',
                    'entityVersion': 1, 'previousRevision': 0, 'operation': operation,
                    'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'outcome': 'committed', 'state': {'format': 'amx-integration-effect-v1',
                        'originalOperationId': operation['operationId'],
                        'originalPayloadDigest': operation['payloadDigest'],
                        'phase': 'intent-committed', 'intent': body},
                    'effects': [{'effectId': self._binding.entity_id, 'contractId': contract,
                        'payloadDigest': operation['payloadDigest'], 'grantRef': operation['grantRef'],
                        'recovery': 'query-before-retry', 'payload': body}],
                    'artifacts': [] if content is None else [content], 'repository': None,
                    'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                        'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': contract}}
                retained_state(record)
                try:
                    stored = await self._ledger.append(record, expected_sequence=0,
                                                       valid_until=decision.valid_until, completion_records=3)
                except ContractError as error:
                    if error.code != 'owner_commit_uncertain':
                        raise
                    try:
                        stored = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
                    except ContractError:
                        raise ContractError('integration_reconciliation_required') from None
                    if stored is None:
                        raise ContractError('integration_reconciliation_required') from None
            state = self._retained(stored)
            record = strict_loads(stored.record)
            if (canonical_bytes(record['operation']) != canonical_bytes(operation)
                    or state['intent'] != body or payload_digest(body) != operation['payloadDigest']):
                raise ContractError('integration_original_identity_conflict')
            await self._authorize(raw, envelope)
            return IntegrationReply(operation['operationId'], operation['operationId'],
                                    operation['payloadDigest'], stored.sequence, 'intent-committed')
