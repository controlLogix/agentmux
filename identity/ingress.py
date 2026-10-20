"""Authenticate enrolled credential possession and construct signed direct calls.

The application proof supplements scoped NATS credentials. It does not infer the
publisher's NKey from a NATS message, nor turn a JSON transport reference into
proof of possession. No private key is generated or enrolled here.
"""
import base64
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import uuid

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                               sign_claims, strict_loads, validate)
from .authority import (approval_reason, _active, _indexes, _key, evaluate_snapshot,
                        DEFINITION_COMMANDS, INTEGRATION_COMMANDS, BOARD_COMMANDS, MESSAGE_COMMANDS,
                        KNOWLEDGE_COMMANDS, CODE_COMMANDS, WORK_COMMANDS, LEGACY_STORAGE_COMMANDS, PEER_CONTROL_COMMANDS,
                        DASHBOARD_COMMANDS, ORCHESTRATION_COMMANDS, ORDINARY_SECRET_PHASE_COMMANDS,
                        EXECUTION_PLAN_COMMANDS, TASK_CREDENTIAL_COMMANDS, EXECUTION_RUN_COMMANDS)
from .capability_routes import CAPABILITY_DESTINATIONS

OWNER_BODY_LIMIT = 65536
LEGACY_MESSAGE_BODY_LIMIT = 1048576
_TERMINAL_SESSION_EXEMPT = frozenset({
    # Protected authority maintenance must remain able to revoke or repair the
    # application session. These routes use their own enrolled owner grants.
    'identity-enroll',
    'identity-revoke',
    'identity-membership-set',
    'identity-grant-set',
    'identity-approval-set',
    'identity-native-instance-set',
    'identity-legacy-alias-set',
    'identity-application-account-set',
    'identity-external-account-link',
    'local-browser-session-open',
    'oidc-terminal-session-open',
    'oidc-terminal-session-status',
    'oidc-terminal-session-close',
})


def verify_possession(claims, signature, public_key):
    """Use the same canonical bytes and Ed25519 library as the existing SDK."""
    try:
        key = base64.urlsafe_b64decode(public_key + '=')
        sig = base64.b64decode(signature + '==', altchars=b'-_', validate=True)
        if (base64.urlsafe_b64encode(key).decode().rstrip('=') != public_key
                or base64.urlsafe_b64encode(sig).decode().rstrip('=') != signature):
            raise ValueError()
        VerifyKey(key).verify(canonical_bytes(claims), sig)
    except (ValueError, TypeError, BadSignatureError):
        raise ContractError('credential_possession_invalid') from None


def _time(value):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise ContractError('credential_time_invalid') from None


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


@dataclass(frozen=True, repr=False)
class AdmittedCall:
    envelope: bytes | None
    decision: object
    audit_envelope: bytes | None = None

    def __repr__(self):
        return '<AdmittedCall private>'


class EnrolledIngress:
    """A host-owned signer pinned to an already enrolled ingress service.

    The reader and signing key must come from the private enrolled profile, never
    a client request. Admission returns bytes; dispatch and durable audit remain
    with the owning service. The caller supplies an owner-allocated cancellation
    reference. That allocation is not delegated to request JSON.
    """
    def __init__(self, reader, *, issuer_ref, signing_seed, session_authorizer=None):
        if (type(signing_seed) is not bytes or len(signing_seed) != 32
                or session_authorizer is not None and not callable(session_authorizer)):
            raise ContractError('invalid_signing_key')
        self._reader = reader
        self._issuer_ref = canonical_bytes(issuer_ref)
        self._seed = signing_seed
        self._session_authorizer = session_authorizer

    def __repr__(self):
        return '<EnrolledIngress private>'

    def require_terminal_sessions(self, authorizer):
        """Enable the owner-side terminal gate after protected configuration."""
        if self._session_authorizer is not None or not callable(authorizer):
            raise ContractError('oidc_terminal_configuration_invalid')
        self._session_authorizer = authorizer

    async def _request_authority(self, request_bytes):
        if type(request_bytes) is not bytes or len(request_bytes) > LEGACY_MESSAGE_BODY_LIMIT:
            raise ContractError('owner_body_limit')
        request = strict_loads(request_bytes)
        validate('identity-ingress-request', request)
        if (request['claims']['contractId'] not in LEGACY_STORAGE_COMMANDS
                and len(request_bytes) > OWNER_BODY_LIMIT):
            raise ContractError('owner_body_limit')
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        claims = request['claims']
        if 'workSource' in claims:
            from .work_client import WORK_COMMANDS
            if claims['contractId'] not in WORK_COMMANDS:
                raise ContractError('credential_source_binding_invalid')
        if (claims['hubId'] != record['ownerHubId'] or claims['profileId'] != state['profileId']
                or claims['authorityId'] != record['entityId']):
            raise ContractError('credential_profile_mismatch')
        issued, expires = _time(claims['issuedAt']), _time(claims['expiresAt'])
        if not issued <= now < expires or expires - issued > timedelta(seconds=60):
            raise ContractError('credential_time_invalid')
        transport = index['transports'].get(_key(claims['transportRef']))
        issuer = index['issuers'].get(_key(strict_loads(self._issuer_ref)))
        if (transport is None or issuer is None or not _active(transport, now)
                or not _active(issuer, now) or transport['issuerRef'] != issuer['ref']
                or transport['method'] != 'nats-credential-mapping'):
            raise ContractError('credential_unavailable')
        verify_possession(claims, request['signature'], transport['publicKey'])
        caller = index['identities'].get(_key(transport['identityRef']))
        grant = index['grants'].get(_key(claims['grantRef']))
        if (caller is None or grant is None or not _active(caller, now) or not _active(grant, now)
                or grant['callerRef'] != caller['ref'] or grant['actorRef'] != caller['ref']
                or grant['delegationRef'] is not None):
            raise ContractError('credential_grant_unavailable')
        return snapshot, now, record, index, claims, transport, issuer, caller, grant, expires

    def _reservation_preflight(self, record, index, claims, issuer, caller, grant, now):
        if claims['contractId'] != 'task-reserve':
            raise ContractError('task_reservation_contract_required')
        validate('task-reserve', claims['payload'])
        state = record['state']
        issuer_identity = index['identities'].get(_key(issuer['identityRef']))
        if (issuer_identity is None or not _active(issuer_identity, now)
                or issuer_identity['kind'] != 'service'):
            raise ContractError('issuer_identity_mismatch')
        task = claims['payload']['taskId']
        if (caller['kind'] == 'plugin' or grant['contractId'] != 'task-reserve'
                or grant['resourceId'] != task or grant['decision'] == 'denied'
                or not any(_active(m, now) and m['identityRef'] == caller['ref'] and m['scope'] == grant['scope']
                           for m in state['memberships'])
                or any(_active(g, now) and g['callerRef'] == caller['ref'] and g['actorRef'] == caller['ref']
                       and g['scope'] == grant['scope'] and g['contractId'] == 'task-reserve'
                       and g['resourceId'] == task and g['decision'] == 'denied' for g in state['grants'])):
            raise ContractError('task_reservation_not_authorized')
        reason = approval_reason(index, grant, {
            'approvalRefs': claims['approvalRefs'], 'payloadDigest': payload_digest(claims['payload']),
            'operationId': claims['operationId'], 'expectedVersion': claims['expectedVersion'],
        }, audience={'hubId': record['ownerHubId'], 'serviceId': 'task-owner'},
            scope=grant['scope'], contract='task-reserve', now=now)
        if reason is not None:
            raise ContractError(reason)

    async def authorize_reservation_preparation(self, request_bytes):
        """Check current possession and authority before a host reads task state.

        Success returns None, not a proof. Admission and the owner must recheck
        authority after preparation and before committing a reservation.
        """
        async with asyncio.timeout(5):
            _, now, record, index, claims, _, issuer, caller, grant, _ = await self._request_authority(request_bytes)
            self._reservation_preflight(record, index, claims, issuer, caller, grant, now)

    async def admit(self, request_bytes, *, cancellation_ref, reservation_context=None):
        snapshot, now, record, index, claims, transport, issuer, caller, grant, expires = await self._request_authority(request_bytes)
        is_reservation = claims['contractId'] == 'task-reserve'
        if not is_reservation and reservation_context is not None:
            raise ContractError('task_reservation_preparation_required')
        if is_reservation:
            from state_owner.task import PreparedTaskReservation
            if type(reservation_context) is not PreparedTaskReservation:
                raise ContractError('task_reservation_preparation_required')
            validate('task-reserve', claims['payload'])
        delegation_ref = None
        if is_reservation:
            self._reservation_preflight(record, index, claims, issuer, caller, grant, now)
            async with asyncio.timeout(min(5, (expires - now).total_seconds())):
                reference = await reservation_context.validate_ingress(self._reader, request_bytes, cancellation_ref)
            if type(reference) is not bytes:
                raise ContractError('task_reservation_preparation_invalid')
            delegation_ref = strict_loads(reference)
            if (canonical_bytes(delegation_ref) != reference
                    or delegation_ref != {'id':claims['payload']['delegationId'],
                        'ownerHubId':record['ownerHubId'], 'revision':1}):
                raise ContractError('task_reservation_preparation_invalid')
            # Owner preparation can await storage. Recheck authority after it.
            snapshot = await self._reader.current()
            now = datetime.now(timezone.utc)
        destinations = {'task-inspect': 'task-owner', 'task-reserve': 'task-owner', 'task-import': 'task-owner', 'definition-save': 'definition-owner',
                        'definition-drop': 'definition-owner'}
        destinations['task-artifact-backup-read'] = 'task-owner'
        destinations['federation-ledger-import'] = 'federation-ledger-owner'
        destinations['federation-policy-project'] = 'configuration-owner'
        destinations['conversation-ledger-import'] = 'conversation-ledger-owner'
        destinations.update(CAPABILITY_DESTINATIONS)
        destinations.update({name: 'integration-owner' for name in INTEGRATION_COMMANDS})
        destinations.update({name: 'definition-owner' for name in DEFINITION_COMMANDS})
        destinations.update({name: 'storage-owner' for name in BOARD_COMMANDS})
        destinations.update({name: 'storage-owner' for name in MESSAGE_COMMANDS})
        destinations.update({name: 'storage-owner' for name in KNOWLEDGE_COMMANDS})
        destinations.update({name: 'storage-owner' for name in CODE_COMMANDS})
        destinations.update({name: 'storage-owner' for name in WORK_COMMANDS})
        destinations.update({name: 'storage-owner' for name in PEER_CONTROL_COMMANDS})
        destinations.update({name: 'dashboard-owner' for name in DASHBOARD_COMMANDS})
        destinations.update({name: 'orchestration-owner' for name in ORCHESTRATION_COMMANDS})
        destinations.update({name: 'secret-owner' for name in ORDINARY_SECRET_PHASE_COMMANDS})
        destinations.update({name: 'process-owner' for name in EXECUTION_PLAN_COMMANDS})
        destinations.update({name: 'process-owner' for name in TASK_CREDENTIAL_COMMANDS | EXECUTION_RUN_COMMANDS})
        destinations.update({name: 'configuration-owner' for name in
            ('configuration-read', 'configuration-set', 'configuration-watch', 'configuration-change',
             'configuration-change-subscribe')})
        destinations['authority-switch'] = 'authority-switch-owner'
        for name in ('identity-enroll', 'identity-revoke', 'identity-membership-set',
                     'identity-grant-set', 'identity-approval-set', 'identity-native-instance-set',
                     'identity-legacy-alias-set', 'identity-legacy-alias-resolve',
                     'identity-external-account-link',
                     'identity-application-account-set', 'identity-application-account-resolve',
                     'identity-ordinary-secret-set', 'identity-ordinary-secret-resolve',
                     'local-browser-session-open', 'oidc-terminal-session-open',
                     'oidc-terminal-session-status', 'oidc-terminal-session-close'):
            destinations[name] = 'identity-owner'
        destination = destinations.get(claims['contractId'])
        if destination is None:
            raise ContractError('authority_contract_unsupported')
        end = min(expires, _time(transport['expiresAt']), _time(issuer['expiresAt']), _time(grant['expiresAt']))
        # Exact request replay keeps its operation lineage and requested deadline.
        # Current authority can shorten the attestation and decision validity,
        # never rewrite the operation already retained by its destination.
        operation = {
            'schemaVersion': '1.0.0', 'operationId': claims['operationId'],
            'payloadDigest': payload_digest(claims['payload']), 'expectedVersion': claims['expectedVersion'],
            'caller': {'principalId': caller['principalId'], 'kind': caller['kind'], 'authenticatedIdentityRef': caller['ref']},
            'effectiveActorRef': caller['ref'], 'scope': grant['scope'],
            'taskId': claims['payload'].get('taskId') if claims['contractId'] in (
                'task-inspect','task-reserve','task-import','task-artifact-backup-read') else None,
            'runId': None,
            'attemptId': (claims['payload']['attemptId']
                          if is_reservation
                          or claims['contractId'] == 'oidc-terminal-session-status'
                          else None),
            'delegationRef': delegation_ref, 'grantRef': grant['ref'],
            'approvalRefs': claims['approvalRefs'], 'traceId': 'trace-' + payload_digest(claims).split(':', 1)[1],
            'causationId': claims['operationId'], 'deadline': claims['expiresAt'],
            'cancellationRef': strict_loads(canonical_bytes(cancellation_ref)),
            **({'terminalSessionId': claims['terminalSessionId']}
               if 'terminalSessionId' in claims else {}),
        }
        signed = {'purpose': 'agentmux-ingress-v1', 'issuerHubId': record['ownerHubId'],
            'signingKeyRef': issuer['ref'], 'authenticationMethod': transport['method'],
            'authenticatedTransportRef': transport['ref'],
            'audience': {'hubId': record['ownerHubId'], 'serviceId': destination},
            'issuedAt': _stamp(now), 'expiresAt': _stamp(end), 'messageId': 'message-' + uuid.uuid4().hex,
            'kind': 'event' if claims['contractId'] == 'configuration-change' else 'command',
            'contractId': claims['contractId'], 'contractMajor': 1,
            'sourceHubId': record['ownerHubId'], 'sourceInstanceId': issuer['instanceId'],
            'sentAt': _stamp(now), 'correlationId': claims['operationId'], 'operation': operation}
        envelope = {key: signed[key] for key in ('messageId', 'kind', 'contractId', 'contractMajor',
                    'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId', 'operation')}
        envelope.update(schemaVersion='1.0.0', destinationHubId=record['ownerHubId'],
                        destinationServiceId=destination, payload=claims['payload'],
                        ingressAttestation={'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
                            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': signed,
                            'signature': sign_claims(signed, self._seed)})
        encoded = canonical_bytes(envelope)
        limit = LEGACY_MESSAGE_BODY_LIMIT if claims['contractId'] in LEGACY_STORAGE_COMMANDS else OWNER_BODY_LIMIT
        if len(encoded) > limit:
            raise ContractError('owner_body_limit')
        decision = evaluate_snapshot(snapshot, encoded, audience=signed['audience'], now=now)
        if (decision.outcome == 'allowed' and self._session_authorizer is not None
                and claims['contractId'] not in _TERMINAL_SESSION_EXEMPT):
            await self.authorize_terminal(operation)
        return AdmittedCall(encoded if decision.outcome == 'allowed' else None, decision,
                            encoded if decision.operation is not None else None)

    async def authorize_terminal(self, operation):
        """Refresh the opaque terminal session for this exact actor and scope."""
        if self._session_authorizer is None:
            return
        session_id = operation.get('terminalSessionId')
        if not isinstance(session_id, str):
            raise ContractError('oidc_terminal_session_required')
        await self._session_authorizer(
            session_id, operation['effectiveActorRef'], operation['scope'])
