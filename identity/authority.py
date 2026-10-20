"""Read retained authority and evaluate direct signed operations.

This is a receiving-owner boundary, not enrollment or a login service. The host
supplies an authenticated, read-scoped JetStream context and pins the aggregate.
An allowed result is not a durable audit receipt or permission to skip the domain
owner's current-state checks, replay check, lock, or conditional commit.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import re

from agentmux_contracts import (ContractError, canonical_bytes, strict_loads,
                               validate, verify_envelope)
from .capability_routes import CAPABILITY_DESTINATIONS

_ID = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
_COLLECTIONS = ('identities', 'issuers', 'transports', 'memberships', 'grants', 'approvals',
                'nativeInstances', 'legacyAliases', 'secretReferences', 'applicationAccounts',
                'ordinarySecretReferences')
INTEGRATION_COMMANDS = frozenset(('integration-intent', 'integration-effect-query',
    'integration-attempt-start', 'integration-attempt-complete', 'integration-effect-reconcile'))
DEFINITION_COMMANDS = frozenset(('definition-save', 'definition-drop',
    'definition-effect-query', 'definition-effect-complete', 'definition-effect-retry'))
BOARD_COMMANDS = frozenset(('federation-board-command', 'federation-board-dispatch', 'federation-board-complete'))
MESSAGE_COMMANDS = frozenset(('federation-message-send', 'federation-message-deliver',
    'federation-message-approve', 'federation-message-inspect', 'federation-message-outcome',
    'federation-message-finding'))
KNOWLEDGE_COMMANDS = frozenset('federation-knowledge-' + action for action in
    ('share', 'index', 'approve', 'capture', 'withdraw', 'read', 'inspect', 'outcome'))
CODE_COMMANDS = frozenset('federation-code-' + action for action in
    ('publish', 'index', 'approve', 'fetched', 'read', 'inspect', 'outcome'))
WORK_SERVICE_COMMANDS = frozenset('federation-work-' + action for action in
    ('ingest', 'claim-envelope', 'grant-envelope', 'result-envelope', 'stage-result',
     'revoke', 'return-leases', 'sweep-leases', 'ingest-legacy', 'result-legacy',
     'register', 'state', 'sweep-global'))
WORK_OPERATOR_COMMANDS = frozenset('federation-work-' + action for action in
    ('cancel', 'approve', 'approve-privileged'))
WORK_COMMANDS = WORK_SERVICE_COMMANDS | WORK_OPERATOR_COMMANDS | frozenset(
    'federation-work-' + action for action in
    ('create', 'offer', 'claim', 'heartbeat', 'release', 'claim-path', 'read', 'inspect', 'outcome'))
LEGACY_STORAGE_COMMANDS = MESSAGE_COMMANDS | KNOWLEDGE_COMMANDS | CODE_COMMANDS | WORK_COMMANDS
PEER_CONTROL_COMMANDS = frozenset(('federation-peer-revoke', 'federation-peer-revoke-outcome'))
DASHBOARD_COMMANDS = frozenset(('dashboard-command', 'dashboard-dispatch',
    'dashboard-effect-complete', 'dashboard-outcome-query'))
ORCHESTRATION_COMMANDS = frozenset(('orchestration-command', 'orchestration-dispatch',
    'orchestration-complete', 'orchestration-outcome-query'))
ORDINARY_SECRET_PHASE_COMMANDS = frozenset(('ordinary-secret-dispatch', 'ordinary-secret-complete'))
TASK_CREDENTIAL_COMMANDS = frozenset(('task-credential-prepare', 'task-credential-deliver',
    'task-credential-observe', 'task-credential-retire'))
EXECUTION_RUN_COMMANDS = frozenset(('execution-run-record', 'execution-run-observe'))
EXECUTION_PLAN_COMMANDS = frozenset(('execution-plan-enroll', 'execution-plan-read', 'execution-plan-revoke'))


def _utc_now():
    return datetime.now(timezone.utc)


def _key(ref):
    return ref['ownerHubId'], ref['id'], ref['revision']


def _active(record, now):
    if record['status'] != 'active':
        return False
    if 'issuedAt' not in record:
        return True
    try:
        start, end = (datetime.fromisoformat(record[k]) for k in ('issuedAt', 'expiresAt'))
        return start <= now < end
    except (ValueError, TypeError):
        raise ContractError('authority_time_invalid') from None


@dataclass(frozen=True, repr=False)
class AuthoritySnapshot:
    """Private immutable bytes read from the pinned authoritative record."""
    record: bytes
    sequence: int

    def __repr__(self):
        return '<AuthoritySnapshot private>'


@dataclass(frozen=True, repr=False)
class Decision:
    outcome: str
    reason: str
    authority_sequence: int
    operation: bytes | None = None
    audit_actor: str | None = None
    authority_ref: bytes | None = None
    valid_until: datetime | None = None

    def __repr__(self):
        return f'<Decision {self.outcome} {self.reason}>'


def authorization_deadline(state, envelope, now):
    """Bound this snapshot's decision by every upcoming authority time change."""
    limits = [datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']),
              datetime.fromisoformat(envelope['operation']['deadline'])]
    for collection in ('issuers', 'transports', 'grants', 'approvals'):
        for item in state[collection]:
            if item['status'] == 'active':
                for field in ('issuedAt', 'expiresAt'):
                    boundary = datetime.fromisoformat(item[field])
                    if boundary > now:
                        limits.append(boundary)
    return min(limits)


class AuthorityReader:
    """Read the leader-backed owner record; never use a KV projection as authority.

    The stream must already be provisioned with retained file storage and scoped
    credentials. This reader cannot enroll or provision an empty installation.
    """
    def __init__(self, jetstream, *, stream, subject, hub_id, entity_id, profile_id, organization_id,
                 timeout=2.0):
        if (not all(isinstance(v, str) and _ID.fullmatch(v)
                    for v in (hub_id, entity_id, profile_id, organization_id))
                or not isinstance(stream, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', stream)
                or not isinstance(subject, str) or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', subject)
                or type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('authority_configuration_invalid')
        self._js = jetstream
        self._stream, self._subject = stream, subject
        self._hub, self._entity, self._profile = hub_id, entity_id, profile_id
        self._organization = organization_id
        self._timeout = timeout

    async def current(self):
        try:
            message = await asyncio.wait_for(self._js.get_msg(
                self._stream, subject=self._subject, direct=False), self._timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('authority_unavailable') from None
        if (getattr(message, 'subject', None) != self._subject or type(getattr(message, 'seq', None)) is not int
                or not 0 < message.seq <= 9007199254740991
                or type(getattr(message, 'data', None)) is not bytes):
            raise ContractError('authority_record_invalid')
        return self._validate_snapshot(message.data, message.seq)

    def _validate_snapshot(self, raw, sequence):
        if len(raw) > 65536:
            raise ContractError('owner_body_limit')
        record = strict_loads(raw)
        validate('owner-record', record)
        if (record['ownerDomain'] != 'identity' or record['entityKind'] != 'identity-authority'
                or record['ownerHubId'] != self._hub or record['entityId'] != self._entity):
            raise ContractError('authority_owner_mismatch')
        state = record['state']
        validate('identity-authority-state', state)
        if state['organizationId'] != self._organization or record['operation']['scope']['organizationId'] != self._organization:
            raise ContractError('authority_organization_mismatch')
        if state['profileId'] != self._profile:
            raise ContractError('authority_profile_mismatch')
        _indexes(state, self._hub)
        return AuthoritySnapshot(canonical_bytes(record), sequence)

    async def evaluate(self, envelope_bytes, *, audience):
        """Call anew after the domain lock and immediately before mutation.

        This read and a different owner's write are not a cross-stream transaction.
        Callers must keep that boundary explicit; no snapshot is a lasting grant.
        """
        snapshot = await self.current()
        return evaluate_snapshot(snapshot, envelope_bytes, audience=audience, now=_utc_now())


class LedgerAuthorityReader(AuthorityReader):
    """Read through the shared ledger's trusted stream identity and history checks."""
    def __init__(self, ledger, *, hub_id, entity_id, profile_id, organization_id):
        from state_owner.ledger import OwnerLedger
        if not isinstance(ledger, OwnerLedger) or not all(
                isinstance(v, str) and _ID.fullmatch(v)
                for v in (hub_id, entity_id, profile_id, organization_id)):
            raise ContractError('authority_configuration_invalid')
        self._ledger = ledger
        self._hub, self._entity = hub_id, entity_id
        self._profile, self._organization = profile_id, organization_id

    async def current(self):
        snapshot = await self._ledger.current()
        if snapshot.latest is None:
            raise ContractError('identity_not_enrolled')
        return self._validate_snapshot(snapshot.latest.record, snapshot.sequence)


def _indexes(state, hub):
    result, seen, principals, external = {}, set(), set(), set()
    for collection in _COLLECTIONS:
        result[collection] = {}
        for item in state.get(collection, []):
            if collection in ('issuers', 'transports', 'grants', 'approvals',
                              'secretReferences', 'applicationAccounts', 'ordinarySecretReferences'):
                try:
                    start, end = (datetime.fromisoformat(item[k])
                                  for k in ('issuedAt', 'expiresAt'))
                    if (start.tzinfo is None or end.tzinfo is None
                            or start.utcoffset() != timezone.utc.utcoffset(start)
                            or end.utcoffset() != timezone.utc.utcoffset(end) or start >= end):
                        raise ValueError()
                except (ValueError, TypeError, KeyError):
                    raise ContractError('authority_time_invalid') from None
            if 'scope' in item and item['scope']['organizationId'] != state['organizationId']:
                raise ContractError('authority_organization_mismatch')
            key = _key(item['ref'])
            identity = key[:2]
            if key[0] != hub or identity in seen:
                raise ContractError('authority_reference_ambiguous')
            seen.add(identity)
            result[collection][key] = item
            if collection == 'identities':
                if item['principalId'] in principals:
                    raise ContractError('authority_principal_ambiguous')
                principals.add(item['principalId'])
                if item['externalIdentity'] is not None:
                    pair = tuple(item['externalIdentity'][k] for k in ('issuer', 'subject'))
                    if pair in external:
                        raise ContractError('authority_external_identity_ambiguous')
                    external.add(pair)
    from .native_records import validate_native_records
    validate_native_records(state, result, hub)
    aliases, sessions = {}, {}
    for item in state.get('legacyAliases', []):
        if item['status'] != 'active':
            continue
        namespace = (item['sourceHubId'], canonical_bytes(item['scope']),
                     canonical_bytes(item['instanceOwner']), item['registrationGeneration'])
        alias_key = namespace + (item['alias'],)
        session_key = namespace + (item['canonicalSession'],)
        target = canonical_bytes(item['identityRef'])
        if alias_key in aliases or (session_key in sessions and sessions[session_key] != target):
            raise ContractError('legacy_identity_collision')
        aliases[alias_key], sessions[session_key] = target, target
    for item in state.get('secretReferences', []):
        if (item['profileId'] != state['profileId']
                or item['scope']['organizationId'] != state['organizationId']
                or item['scope']['projectId'] is None
                or item['scope']['workspaceId'] is not None):
            raise ContractError('application_account_scope_mismatch')
    for item in state.get('applicationAccounts', []):
        if (item['profileId'] != state['profileId']
                or item['scope']['organizationId'] != state['organizationId']
                or item['scope']['projectId'] is None
                or item['scope']['workspaceId'] is not None):
            raise ContractError('application_account_scope_mismatch')
    return result


def approval_reason(index, grant, operation, *, audience, scope, contract, now):
    """Apply the same current approval rules before and after owner preparation."""
    def lookup(collection, reference):
        item = index[collection].get(_key(reference))
        return item if item is not None and _active(item, now) else None

    approvals = [lookup('approvals', ref) for ref in operation['approvalRefs']]
    for approval in approvals:
        if (approval is None or approval['grantRef'] != grant['ref']
                or approval['payloadDigest'] != operation['payloadDigest']
                or approval['audience'] != audience
                or approval['operationId'] != operation['operationId']
                or approval['expectedVersion'] != operation['expectedVersion']
                or lookup('identities', approval['approverRef']) is None):
            return 'approval_binding_mismatch'
        approver_grant = lookup('grants', approval['approverGrantRef'])
        approval_grants = [g for g in index['grants'].values()
            if _active(g, now) and g['callerRef'] == approval['approverRef']
            and g['actorRef'] == approval['approverRef'] and g['scope'] == scope
            and g['contractId'] == 'identity-approve' and g['resourceId'] == grant['ref']['id']]
        if (approver_grant is None or approver_grant not in approval_grants
                or approver_grant['decision'] != 'allowed' or approver_grant['delegationRef'] is not None
                or any(g['decision'] == 'denied' for g in approval_grants)
                or not any(_active(m, now) and m['identityRef'] == approval['approverRef']
                           and m['scope'] == scope for m in index['memberships'].values())):
            return 'approval_authority_unavailable'
    if any(a['decision'] == 'rejected' for a in approvals):
        return 'approval_rejected'
    if (grant['decision'] == 'review-required' or contract in ('integration-intent', 'integration-attempt-start')) and not approvals:
        return 'approval_required'
    return None


def _approved_secret_outcome(index, grants, payload, *, scope, now):
    """Check current approval for a new read of the exact historical effect."""
    original = payload['input']
    if (original['contractId'] != 'capability-secret-use'
            or payload['resourceRef']['revision'] != 1):
        return False
    audience = {'hubId': payload['resourceRef']['ownerHubId'], 'serviceId': 'secret-owner'}
    for grant in grants:
        if grant['decision'] != 'review-required':
            continue
        for approval in index['approvals'].values():
            operation = {'operationId': original['operationId'],
                'payloadDigest': original['payloadDigest'],
                'expectedVersion': payload['resourceRef']['revision'],
                'approvalRefs': [approval['ref']]}
            if approval_reason(index, grant, operation, audience=audience,
                    scope=scope, contract='capability-secret-use', now=now) is None:
                return True
    return False


def evaluate_snapshot(snapshot, envelope_bytes, *, audience, now):
    """Evaluate a trusted owner snapshot; supplied bytes alone are not enrollment.

    Kept separate for offline security tests. Production callers use AuthorityReader
    to obtain current retained state. No verifier or allow callback is accepted.
    """
    if (not isinstance(now, datetime) or now.tzinfo is None
            or now.utcoffset() != timezone.utc.utcoffset(now)):
        raise ContractError('invalid_clock')
    if type(envelope_bytes) is not bytes or len(envelope_bytes) > 1048576:
        raise ContractError('owner_body_limit')
    if len(snapshot.record) > 65536:
        raise ContractError('owner_body_limit')
    record = strict_loads(snapshot.record)
    validate('owner-record', record)
    validate('identity-authority-state', record['state'])
    if record['entityKind'] != 'identity-authority' or record['ownerDomain'] != 'identity':
        raise ContractError('authority_owner_mismatch')
    if record['state']['organizationId'] != record['operation']['scope']['organizationId']:
        raise ContractError('authority_organization_mismatch')
    index = _indexes(record['state'], record['ownerHubId'])
    envelope = strict_loads(envelope_bytes)
    validate('message-envelope', envelope)
    if envelope['contractId'] not in LEGACY_STORAGE_COMMANDS and len(envelope_bytes) > 65536:
        raise ContractError('owner_body_limit')
    claims = envelope['ingressAttestation']['claims']

    admitted_operation, admitted_actor = None, None
    resource_deadline = None

    def decision_deadline():
        deadline = authorization_deadline(record['state'], envelope, now)
        return min(deadline, resource_deadline) if resource_deadline is not None else deadline

    def deny(reason):
        return Decision('denied', reason, snapshot.sequence, admitted_operation, admitted_actor)

    def lookup(collection, reference):
        item = index[collection].get(_key(reference))
        return item if item is not None and _active(item, now) else None

    issuer = lookup('issuers', claims['signingKeyRef'])
    if issuer is None:
        return deny('issuer_unavailable')
    issuer_identity = lookup('identities', issuer['identityRef'])
    if (issuer_identity is None or issuer_identity['kind'] != 'service'
            or issuer['instanceId'] != claims['sourceInstanceId']
            or claims['sourceHubId'] != record['ownerHubId']):
        return deny('issuer_identity_mismatch')
    public_key = base64.urlsafe_b64decode(issuer['publicKey'] + '=')
    # The canonical SDK validates the signature, registered payload and full binding.
    verify_envelope(envelope, public_key, audience, now)
    operation = claims['operation']
    transport = lookup('transports', claims['authenticatedTransportRef'])
    caller_ref = operation['caller']['authenticatedIdentityRef']
    caller = lookup('identities', caller_ref)
    actor = lookup('identities', operation['effectiveActorRef'])
    if (transport is None or caller is None or actor is None
            or transport['issuerRef'] != issuer['ref']
            or transport['identityRef'] != caller_ref
            or transport['method'] != claims['authenticationMethod']
            or caller['principalId'] != operation['caller']['principalId']
            or caller['kind'] != operation['caller']['kind']):
        return deny('identity_binding_mismatch')
    reservation_correlation = envelope['contractId'] == 'task-reserve'
    if (caller_ref != actor['ref']
            or operation['delegationRef'] is not None and not reservation_correlation):
        return deny('delegation_not_supported')
    admitted_operation, admitted_actor = canonical_bytes(operation), actor['principalId']
    scope = operation['scope']
    if not any(_active(m, now) and m['identityRef'] == actor['ref'] and m['scope'] == scope
               for m in index['memberships'].values()):
        return deny('membership_unavailable')
    contract, payload = envelope['contractId'], envelope['payload']
    if contract in DEFINITION_COMMANDS:
        if (caller['kind'] != 'human'
                or (payload['scope'] == 'global' and (scope['projectId'] is not None or scope['workspaceId'] is not None))
                or (payload['scope'] == 'repo' and scope['projectId'] is None)):
            return deny('definition_scope_mismatch')
        resource = payload['definitionId']
    elif contract in ('identity-enroll', 'identity-revoke', 'identity-membership-set',
                       'identity-grant-set', 'identity-approval-set', 'identity-native-instance-set',
                       'identity-external-account-link', 'identity-application-account-set',
                       'identity-ordinary-secret-set'):
        if payload['authorityId'] != record['entityId']:
            return deny('authority_owner_mismatch')
        if scope['projectId'] is not None or scope['workspaceId'] is not None:
            return deny('identity_organization_admin_required')
        resource = record['entityId']
    elif contract == 'identity-ordinary-secret-resolve':
        resource = payload['secretRef']['id']
        if (payload['authorityId'] != record['entityId']
                or payload['profileId'] != record['state']['profileId']
                or payload['scope'] != scope or scope['projectId'] is None
                or caller['kind'] != 'service' or operation['expectedVersion'] != 0):
            return deny('ordinary_secret_scope_mismatch')
    elif contract in ORDINARY_SECRET_PHASE_COMMANDS:
        reference = payload['resourceRef']
        resource = reference['id']
        generations = [item for item in index['ordinarySecretReferences'].values()
                       if item['generationRef'] == reference]
        if (caller['kind'] != 'service' or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != 1 or len(generations) != 1
                or payload['journalRef']['ownerHubId'] != record['ownerHubId']
                or payload['claimRef']['ownerHubId'] != record['ownerHubId']
                or payload['journalRef']['revision'] != operation['expectedVersion']
                or payload['originalOperationId'] == operation['operationId']):
            return deny('ordinary_secret_phase_binding_mismatch')
        generation = generations[0]
        enrolled_scope = generation['scope']
        if (generation['ownerIdentityRef'] != caller_ref
                or generation['ownerAudience'] != audience
                or generation['profileId'] != record['state']['profileId']
                or scope['organizationId'] != enrolled_scope['organizationId']
                or scope['projectId'] != enrolled_scope['projectId']
                or enrolled_scope['workspaceId'] is not None
                    and scope['workspaceId'] != enrolled_scope['workspaceId']):
            return deny('ordinary_secret_phase_binding_mismatch')
        if contract == 'ordinary-secret-dispatch':
            from .ordinary_secret import validate_enrollment
            if not _active(generation, now) or generation['ref'] != reference:
                return deny('ordinary_secret_generation_unavailable')
            try:
                validate_enrollment(record['state'], index, generation, record['ownerHubId'])
            except ContractError:
                return deny('ordinary_secret_generation_unavailable')
            resource_deadline = datetime.fromisoformat(generation['expiresAt'])
        # Completion can retain an already observed effect after original caller
        # revocation or rotation. The owner checks its exact retained dispatch;
        # a public receipt still needs current original Secret.Use authority.
    elif contract == 'identity-application-account-resolve':
        resource = payload['accountRef']['id']
        if (payload['authorityId'] != record['entityId']
                or payload['profileId'] != record['state']['profileId']
                or payload['scope'] != operation['scope']
                or scope['projectId'] is None or scope['workspaceId'] is not None
                or caller['kind'] == 'plugin' or operation['expectedVersion'] != 0):
            return deny('application_account_scope_mismatch')
    elif contract == 'identity-legacy-alias-resolve':
        resource = record['entityId']
        if (payload['authorityId'] != record['entityId']
                or caller['kind'] == 'plugin'
                or scope['projectId'] is None
                or operation['expectedVersion'] != 0):
            return deny('legacy_identity_scope_mismatch')
    elif contract == 'local-browser-session-open':
        resource = record['entityId']
        if (caller['kind'] != 'human' or scope['projectId'] is None
                or operation['expectedVersion'] != 0):
            return deny('local_browser_scope_mismatch')
    elif contract in ('oidc-terminal-session-open', 'oidc-terminal-session-status',
                       'oidc-terminal-session-close'):
        resource = record['entityId']
        if (caller['kind'] != 'human' or scope['projectId'] is None
                or operation['expectedVersion'] != 0):
            return deny('oidc_terminal_scope_mismatch')
    elif contract in INTEGRATION_COMMANDS:
        resource = payload['effectRef']['id']
        if (payload['effectRef']['ownerHubId'] != record['ownerHubId']
                or scope['projectId'] is None
                or payload['effectRef']['revision'] != operation['expectedVersion']):
            return deny('integration_scope_or_version_mismatch')
        if caller['kind'] == 'plugin':
            return deny('native_capability_admission_required')
        if contract != 'integration-intent':
            if operation['operationId'] == payload['originalOperationId']:
                return deny('integration_operation_binding')
            if contract != 'integration-effect-query':
                attempt = payload['attemptOperationId']
                if (attempt == payload['originalOperationId']
                        or (contract == 'integration-attempt-start' and attempt != operation['operationId'])
                        or (contract != 'integration-attempt-start' and attempt == operation['operationId'])):
                    return deny('integration_operation_binding')
            original = [g for g in index['grants'].values() if _active(g, now)
                and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == 'integration-intent' and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('integration_original_authority_unavailable')
    elif contract == 'conversation-ledger-import':
        resource = payload['archiveId']
        if caller['kind'] not in ('human', 'service'):
            return deny('native_capability_admission_required')
        if (scope['projectId'] is not None or scope['workspaceId'] is not None
                or operation['expectedVersion'] != 0
                or any(operation[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))
                or payload['artifactRef']['ownerHubId'] != record['ownerHubId']
                or payload['artifactRef']['storeRef']['ownerHubId'] != record['ownerHubId']):
            return deny('conversation_import_binding_mismatch')
    elif contract == 'federation-ledger-import':
        resource = payload['archiveId']
        if caller['kind'] not in ('human', 'service'):
            return deny('native_capability_admission_required')
        if (scope['projectId'] is not None or scope['workspaceId'] is not None
                or payload['sourceArchive']['sourceOwnerOrganizationId'] != scope['organizationId']
                or operation['expectedVersion'] != 0
                or any(operation[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))):
            return deny('federation_import_binding_mismatch')
    elif contract == 'authority-switch':
        resource = payload['switchId']
        expected = {'record-source-fence': 0, 'open-target-admission': 1,
            'fence-target': 2, 'verify-reverse-migration': 3}
        required = 1 if payload['action'] == 'request-recovery' else expected.get(payload['action'])
        if (caller['kind'] == 'plugin'
                or scope['projectId'] is not None or scope['workspaceId'] is not None
                or any(operation[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))
                or required is not None and operation['expectedVersion'] != required
                or required is None):
            return deny('authority_switch_binding_mismatch')
    elif contract in ('task-inspect', 'task-reserve', 'task-import', 'task-artifact-backup-read'):
        resource = payload['taskId']
        if contract == 'task-artifact-backup-read':
            if (caller['kind'] != 'service' or operation['taskId'] != resource
                    or operation['expectedVersion'] != payload['sourceRevision']
                    or operation['runId'] is not None or operation['attemptId'] is not None
                    or payload['artifactRef']['ownerHubId'] != record['ownerHubId']
                    or payload['artifactRef']['storeRef']['ownerHubId'] != record['ownerHubId']):
                return deny('task_artifact_backup_binding_mismatch')
        if contract == 'task-import':
            if caller['kind'] == 'plugin':
                return deny('native_capability_admission_required')
            if (operation['expectedVersion'] != 0 or operation['taskId'] != resource
                    or operation['attemptId'] is not None or operation['runId'] is not None):
                return deny('task_import_binding_mismatch')
        if contract == 'task-reserve':
            correlation = operation['delegationRef']
            if caller['kind'] == 'plugin':
                return deny('native_capability_admission_required')
            if (correlation is None or correlation['id'] != payload['delegationId']
                    or correlation['ownerHubId'] != record['ownerHubId']
                    or correlation['revision'] != 1):
                return deny('task_reservation_correlation_invalid')
    elif contract in PEER_CONTROL_COMMANDS:
        reference = payload['resourceRef']
        resource = reference['id']
        if (caller['kind'] != 'human' or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != operation['expectedVersion']):
            return deny('peer_control_scope_or_actor_mismatch')
        if contract == 'federation-peer-revoke-outcome':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == 'federation-peer-revoke' and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] in ('allowed', 'review-required') for g in original)):
                return deny('peer_control_original_authority_unavailable')
    elif contract in KNOWLEDGE_COMMANDS:
        if caller['kind'] == 'plugin':
            return deny('native_capability_admission_required')
        reference = payload['resourceRef']
        resource = reference['id']
        if (reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != operation['expectedVersion']
                or contract in ('federation-knowledge-index', 'federation-knowledge-capture',
                    'federation-knowledge-withdraw') and caller['kind'] != 'service'
                or contract == 'federation-knowledge-share' and caller['kind'] not in ('human', 'device')):
            return deny('knowledge_scope_or_actor_mismatch')
        if contract == 'federation-knowledge-approve' and caller['kind'] != 'human':
            return deny('knowledge_scope_or_actor_mismatch')
        if contract == 'federation-knowledge-outcome':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == payload['input']['contractId'] and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('knowledge_original_authority_unavailable')
    elif contract in CODE_COMMANDS:
        if caller['kind'] == 'plugin':
            return deny('native_capability_admission_required')
        reference = payload['resourceRef']
        resource = reference['id']
        if (scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != operation['expectedVersion']
                or contract == 'federation-code-index' and caller['kind'] != 'service'
                or contract in ('federation-code-publish', 'federation-code-fetched')
                    and caller['kind'] not in ('human', 'device')
                or contract == 'federation-code-approve' and caller['kind'] != 'human'):
            return deny('code_scope_or_actor_mismatch')
        if contract == 'federation-code-outcome':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == payload['input']['contractId'] and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('code_original_authority_unavailable')
    elif contract in WORK_COMMANDS:
        if caller['kind'] == 'plugin':
            return deny('native_capability_admission_required')
        reference = payload['resourceRef']
        resource = reference['id']
        if (reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != operation['expectedVersion']
                or scope['projectId'] is None and contract not in
                    ('federation-work-read', 'federation-work-inspect', 'federation-work-outcome')
                or contract in WORK_SERVICE_COMMANDS and caller['kind'] != 'service'
                or contract in WORK_OPERATOR_COMMANDS and caller['kind'] != 'human'
                or contract not in (WORK_SERVICE_COMMANDS | WORK_OPERATOR_COMMANDS | {
                    'federation-work-read', 'federation-work-inspect', 'federation-work-outcome'})
                    and caller['kind'] not in ('human', 'device')):
            return deny('work_scope_or_actor_mismatch')
        if contract == 'federation-work-outcome':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == payload['input']['contractId'] and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('work_original_authority_unavailable')
    elif contract in MESSAGE_COMMANDS:
        if caller['kind'] == 'plugin':
            return deny('native_capability_admission_required')
        reference = payload['resourceRef']
        resource = reference['id']
        if (reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != operation['expectedVersion']
                or contract in ('federation-message-deliver', 'federation-message-finding') and caller['kind'] != 'service'
                or contract == 'federation-message-approve' and caller['kind'] != 'human'):
            return deny('message_scope_or_actor_mismatch')
        if contract == 'federation-message-outcome':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == payload['input']['contractId'] and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('message_original_authority_unavailable')
    elif contract in BOARD_COMMANDS:
        resource = payload['resourceRef']['id']
        reference = payload['resourceRef'] if contract == 'federation-board-command' else payload['journalRef']
        if (payload['resourceRef']['ownerHubId'] != record['ownerHubId']
                or reference['ownerHubId'] != record['ownerHubId']
                or contract != 'federation-board-command' and caller['kind'] != 'service'
                or reference['revision'] != operation['expectedVersion']):
            return deny('board_scope_or_version_mismatch')
    elif contract in DASHBOARD_COMMANDS:
        reference = payload['resourceRef']
        resource = reference['id']
        version_reference = (payload['journalRef']
            if contract in ('dashboard-dispatch', 'dashboard-effect-complete')
            else reference)
        target = payload['target']
        selected_action = ('run-review' if re.fullmatch(
            r'/api/runs/[0-9a-f]{6}/review', target)
            else target.rsplit('/', 1)[-1])
        if (reference['ownerHubId'] != record['ownerHubId']
                or version_reference['ownerHubId'] != record['ownerHubId']
                or version_reference['revision'] != operation['expectedVersion']
                or scope['projectId'] is None):
            return deny('dashboard_scope_or_version_mismatch')
        if payload['action'] != selected_action:
            return deny('dashboard_operation_binding')
        if contract == 'dashboard-command':
            if (caller['kind'] != 'human'
                    or payload['requestId'] != operation['operationId']):
                return deny('dashboard_operation_binding')
        elif contract in ('dashboard-dispatch', 'dashboard-effect-complete'):
            if (caller['kind'] != 'service'
                    or payload['journalRef']['ownerHubId'] != record['ownerHubId']
                    or payload['claimRef']['ownerHubId'] != record['ownerHubId']
                    or payload['originalOperationId'] == operation['operationId']):
                return deny('dashboard_operation_binding')
        else:
            if (caller['kind'] != 'human'
                    or payload['originalOperationId'] == operation['operationId']):
                return deny('dashboard_operation_binding')
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref
                and g['actorRef'] == actor['ref'] and g['scope'] == scope
                and g['resourceId'] == resource and g['contractId'] == 'dashboard-command'
                and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('dashboard_original_authority_unavailable')
    elif contract in ORCHESTRATION_COMMANDS:
        reference = payload['resourceRef']
        resource = reference['id']
        version_reference = (payload['journalRef']
            if contract in ('orchestration-dispatch', 'orchestration-complete')
            else reference)
        if (reference['ownerHubId'] != record['ownerHubId']
                or version_reference['ownerHubId'] != record['ownerHubId']
                or version_reference['revision'] != operation['expectedVersion']
                or scope['projectId'] is None):
            return deny('orchestration_scope_or_version_mismatch')
        if contract == 'orchestration-command':
            environment = payload['environmentRef']
            if (caller['kind'] != 'human'
                    or environment is not None
                    and environment['ownerHubId'] != record['ownerHubId']):
                return deny('orchestration_operation_binding')
        elif contract in ('orchestration-dispatch', 'orchestration-complete'):
            if (caller['kind'] != 'service'
                    or payload['journalRef']['ownerHubId'] != record['ownerHubId']
                    or payload['claimRef']['ownerHubId'] != record['ownerHubId']
                    or payload['originalOperationId'] == operation['operationId']):
                return deny('orchestration_operation_binding')
        else:
            if (caller['kind'] != 'human'
                    or payload['originalOperationId'] == operation['operationId']):
                return deny('orchestration_operation_binding')
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref
                and g['actorRef'] == actor['ref'] and g['scope'] == scope
                and g['resourceId'] == resource and g['contractId'] == 'orchestration-command'
                and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not any(g['decision'] == 'allowed' for g in original)):
                return deny('orchestration_original_authority_unavailable')
    elif contract == 'configuration-change-subscribe':
        from agentmux_contracts import payload_digest
        resource = payload['resourceRef']['id']
        selected_filter = {k: payload[k] for k in ('resourceRef', 'eventContractId', 'filter')}
        if (payload['resourceRef']['ownerHubId'] != record['ownerHubId']
                or caller['kind'] == 'plugin'
                or payload['filterDigest'] != payload_digest(selected_filter)
                or payload['cursor']['sequence'] < payload['resourceRef']['revision']):
            return deny('configuration_subscription_binding')
    elif contract == 'federation-policy-project':
        reference = payload['configurationRef']
        resource = reference['id']
        if (caller['kind'] != 'service' or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] < 1 or reference['revision'] != operation['expectedVersion']
                or payload['target']['sourceRef']['ownerHubId'] != record['ownerHubId']):
            return deny('federation_policy_projection_binding')
    elif contract in ('configuration-read', 'configuration-set', 'configuration-watch', 'configuration-change'):
        resource = payload['configurationRef']['id']
        if (payload['configurationRef']['ownerHubId'] != record['ownerHubId']
                or caller['kind'] == 'plugin'
                or contract == 'configuration-change' and caller['kind'] != 'service'
                or (contract == 'configuration-set' and
                    payload['configurationRef']['revision'] != operation['expectedVersion'])):
            return deny('configuration_scope_or_version_mismatch')
    elif contract in EXECUTION_RUN_COMMANDS:
        reference = payload['runRef']
        resource = reference['id']
        if (caller['kind'] != 'service' or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId'] or reference['revision'] != 1):
            return deny('execution_run_scope_or_actor_mismatch')
    elif contract in TASK_CREDENTIAL_COMMANDS:
        reference = payload['credentialRef']
        resource = reference['id']
        if (caller['kind'] != 'service' or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']
                or reference['revision'] != 1
                or payload['runRef']['ownerHubId'] != record['ownerHubId']):
            return deny('task_credential_scope_or_actor_mismatch')
    elif contract in EXECUTION_PLAN_COMMANDS:
        reference = payload['plan']['ref'] if contract == 'execution-plan-enroll' else payload['planRef']
        resource = reference['id']
        if (caller['kind'] not in ('human', 'service') or scope['projectId'] is None
                or reference['ownerHubId'] != record['ownerHubId']):
            return deny('execution_plan_scope_or_actor_mismatch')
    elif contract in CAPABILITY_DESTINATIONS:
        if payload['resourceRef']['ownerHubId'] != record['ownerHubId']:
            return deny('capability_owner_mismatch')
        if caller['kind'] == 'plugin':
            # A direct plugin credential cannot bypass its native declaration,
            # generation, parent and Go capability-intersection checks.
            return deny('native_capability_admission_required')
        resource = payload['resourceRef']['id']
        if (contract == 'capability-storage-write'
                and operation['expectedVersion'] != payload['resourceRef']['revision']):
            return deny('capability_version_mismatch')
        if contract == 'capability-outcome-query':
            original = [g for g in index['grants'].values()
                if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
                and g['scope'] == scope and g['resourceId'] == resource
                and g['contractId'] == payload['input']['contractId'] and g['delegationRef'] is None]
            if (any(g['decision'] == 'denied' for g in original)
                    or not (any(g['decision'] == 'allowed' for g in original)
                        or _approved_secret_outcome(index, original, payload, scope=scope, now=now))):
                return deny('capability_original_authority_unavailable')
    else:
        return deny('authority_contract_unsupported')
    matches = [g for g in index['grants'].values()
               if _active(g, now) and g['callerRef'] == caller_ref and g['actorRef'] == actor['ref']
               and g['scope'] == scope and g['contractId'] == contract and g['resourceId'] == resource]
    if contract in DEFINITION_COMMANDS:
        target = {'name': payload['name'], 'scope': payload['scope']}
        matches = [g for g in matches if g['definitionTarget'] == target]
    if any(g['decision'] == 'denied' for g in matches):
        return deny('hard_denial')
    grant = lookup('grants', operation['grantRef'])
    if grant is None or grant not in matches or grant['delegationRef'] is not None:
        return deny('grant_unavailable')
    reason = approval_reason(index, grant, operation, audience=audience, scope=scope, contract=contract, now=now)
    if reason == 'approval_required':
        return Decision('review-required', reason, snapshot.sequence, admitted_operation, admitted_actor,
                        valid_until=decision_deadline())
    if reason is not None:
        return deny(reason)
    return Decision('allowed', 'current_authority', snapshot.sequence,
                    canonical_bytes(operation), actor['principalId'],
                    canonical_bytes({'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                                     'revision': record['entityVersion']}),
                    decision_deadline())
