"""Identity commands over a host-owned, scoped NATS connection.

The host supplies enrolled keys, stream identity and retention policy. This module
never connects anonymously, provisions a stream or learns enrollment from it.
"""
import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
import re
import time
import uuid
from pathlib import Path
from state_owner.backup_lifecycle import OwnerBackupLifecycle
from state_owner.checkpoints import CheckpointCadence
from .checkpoint import CheckpointReceipt, export_verified_prefix

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
from .authority import LedgerAuthorityReader
from .commands import IdentityCommandOwner, IDENTITY_COMMANDS
from .ingress import EnrolledIngress, verify_possession
from .native_bridge import NativeAuthorityProvider
from .application_binding import ApplicationBindingProvider

_MAX_OIDC_TERMINAL_ATTEMPTS = 8
_MAX_OIDC_TERMINAL_SESSIONS = 4
_MAX_OIDC_TERMINAL_RESULTS = 64


class IdentityService:
    def __init__(self, connection, *, stream, stream_identity, retention,
                 hub_id, entity_id, profile_id, organization_id, issuer_ref, signing_seed, application_lease=None,
                 history=None, checkpoint_path=None, checkpoint_committed=None,
                 backup_host=None, backup_key_id=None, jetstream_domain=None):
        scope = canonical_bytes({'organizationId': organization_id, 'projectId': None, 'workspaceId': None})
        binding = OwnerBinding(hub_id, 'identity', entity_id, 'identity-authority', scope)
        self.ledger = OwnerLedger(connection.jetstream(domain=jetstream_domain) if jetstream_domain is not None else connection.jetstream(), stream=stream,
            subject=owner_subject(binding), binding=binding, retention=retention,
            stream_identity=stream_identity, history=history, require_completion_budget=True)
        self.reader = LedgerAuthorityReader(self.ledger, hub_id=hub_id, entity_id=entity_id,
            profile_id=profile_id, organization_id=organization_id)
        self.ingress = EnrolledIngress(self.reader, issuer_ref=issuer_ref,
            signing_seed=signing_seed)
        self.owner = IdentityCommandOwner(self.ledger, hub_id=hub_id, entity_id=entity_id,
            profile_id=profile_id, organization_id=organization_id)
        self.native = NativeAuthorityProvider(self.reader, issuer_ref=issuer_ref, signing_seed=signing_seed,
                                             command_owner=self.owner)
        self._application_lock = asyncio.Lock()
        self._application_lease = application_lease
        self.application = (ApplicationBindingProvider(self.reader, observation_lease=application_lease,
            issuer_ref=issuer_ref, signing_seed=signing_seed) if application_lease is not None else None)
        self._history = history
        self._checkpoint_path = checkpoint_path
        self._checkpoint_committed = checkpoint_committed
        self._binding, self._stream_identity = binding, stream_identity
        self._backup = (OwnerBackupLifecycle(history, binding, stream_identity, backup_host,
            key_id=backup_key_id, retrieve_artifact=self._unexpected_artifact)
            if backup_host is not None else None)
        self._cadence = CheckpointCadence(now=time.monotonic())
        self._checkpoint_task = None
        self._checkpoint_work = None
        self._checkpoint_stop = asyncio.Event()
        self._recovery_lock = asyncio.Lock()
        self._connection = connection
        self._seed = signing_seed
        self._issuer = canonical_bytes(issuer_ref)
        self._hub, self._entity, self._profile = hub_id, entity_id, profile_id
        self._subject = '.'.join(('amx', 'v1', 'h', hub_id, 'o', organization_id,
                                  'identity', entity_id, 'command'))
        self._subscription = None
        self._subscribe_task = None
        self._startup_task = None
        self._closed = False
        self._lifecycle_lock = asyncio.Lock()
        self._drain_task = None
        self._active = set()
        self._legacy_identity = None
        self._local_browser_host = None
        self._oidc_terminal = None
        self._oidc_terminal_attempts = {}
        self._oidc_terminal_sessions = {}
        self._oidc_terminal_results = {}
        self._oidc_terminal_lock = asyncio.Lock()

    def __repr__(self):
        return '<IdentityService private>'

    @property
    def subject(self):
        return self._subject

    def replace_application_lease(self, lease):
        """Called only by the host after ending the previous runtime generation."""
        previous = self._application_lease
        if self._closed or (previous is not None and
                (not previous.done.is_set() or lease.generation <= previous.generation
                 or lease.lifetime_id == previous.lifetime_id)):
            raise ContractError('application_generation_mismatch')
        provider = ApplicationBindingProvider(self.reader, observation_lease=lease,
            issuer_ref=strict_loads(self._issuer), signing_seed=self._seed)
        self._application_lease, self.application = lease, provider

    def configure_legacy_identity(self, adapter):
        """Install the first-party project resolver selected by the host owner."""
        from .legacy_identity import LegacyIdentityAdapter
        if (self._closed or self._legacy_identity is not None
                or type(adapter) is not LegacyIdentityAdapter
                or adapter._reader is not self.reader
                or adapter.local_source_hub_id != self._hub
                or adapter.scope['organizationId'] != self.reader._organization
                or adapter.scope['projectId'] is None
                or adapter.instance_owner is not None):
            raise ContractError('legacy_identity_configuration_invalid')
        self._legacy_identity = adapter

    def configure_local_browser_host(self, host):
        """Attach the exact same-process application host for browser pairing."""
        from application_service_host import ApplicationServiceHost
        if (self._closed or self._local_browser_host is not None
                or not isinstance(host, ApplicationServiceHost)):
            raise ContractError('local_browser_host_configuration')
        self._local_browser_host = host

    def configure_oidc_terminal(self, owner):
        """Attach the host-owned terminal login owner to this identity route."""
        from .oidc_terminal_login import OIDCTerminalLoginOwner
        if (self._closed or self._oidc_terminal is not None
                or type(owner) is not OIDCTerminalLoginOwner
                or owner._identity is not self):
            raise ContractError('oidc_terminal_configuration_invalid')
        self._oidc_terminal = owner
        self.ingress.require_terminal_sessions(self.authorize_oidc_terminal)

    async def authorize_oidc_terminal(self, session_id, caller, scope):
        """Resolve one opaque session and refresh its enrolled human authority."""
        if self._oidc_terminal is None:
            return None
        async with self._oidc_terminal_lock:
            await self._prune_oidc_terminal(datetime.now(timezone.utc))
            row = self._oidc_terminal_sessions.get(session_id)
            if (row is None or row['caller'] != caller or row['scope'] != scope):
                raise ContractError('oidc_terminal_session_required')
            context = await row['session'].authorize()
            if context.caller_ref != caller or context.scope != scope:
                raise ContractError('oidc_terminal_session_required')
            return context

    async def execution_terminal_deadline(self, operation):
        """Return the actual finite session bound after current human checks."""
        session_id=operation.get('terminalSessionId')
        if self._oidc_terminal is None or not isinstance(session_id,str):
            raise ContractError('oidc_terminal_session_required')
        async with self._oidc_terminal_lock:
            await self._prune_oidc_terminal(datetime.now(timezone.utc))
            row=self._oidc_terminal_sessions.get(session_id)
            if (row is None or row['caller']!=operation['effectiveActorRef'] or row['scope']!=operation['scope']):
                raise ContractError('oidc_terminal_session_required')
            context=await row['session'].authorize()
            if context.caller_ref!=row['caller'] or context.scope!=row['scope']:
                raise ContractError('oidc_terminal_session_required')
            return min(row['expiresAt'],row['session'].expires_at)

    async def _unexpected_artifact(self, reference):
        # Identity records do not own external artifacts. Never omit one from a
        # backup if an unsupported reference appears in retained history.
        raise ContractError('identity_backup_artifact_unavailable')

    def check_health(self):
        if self._closed:
            raise ContractError('identity_service_closed')
        if self._backup is not None:
            self._backup.check()
        for task in (self._startup_task, self._checkpoint_task, self._checkpoint_work):
            if task is not None and task.done():
                task.result()

    async def handle(self, request_bytes):
        self.check_health()
        if self._checkpoint_work is not None and self._checkpoint_work.done():
            self._checkpoint_work.result()
        if self._checkpoint_task is not None and self._checkpoint_task.done():
            self._checkpoint_task.result()
        completed = asyncio.get_running_loop().create_future()
        self._active.add(completed)
        try:
            if self._history is not None:
                await self._recover()
            response = await self._handle(request_bytes)
            self._checkpoint_if_due()
            return response
        finally:
            self._active.discard(completed)
            completed.set_result(None)

    async def _handle(self, request_bytes):
        if self._closed:
            raise ContractError('identity_service_closed')
        if type(request_bytes) is not bytes or len(request_bytes) > 65536:
            raise ContractError('owner_body_limit')
        request = strict_loads(request_bytes)
        if type(request) is not dict or type(request.get('claims')) is not dict:
            raise ContractError('identity_request_invalid')
        if request.get('claims', {}).get('purpose') == 'agentmux-native-authority-request-v1':
            return await self.native.handle(request_bytes)
        if request['claims'].get('purpose') == 'agentmux-application-observation-update-v1':
            from .observation_updates import update_observation
            return await update_observation(self, request_bytes)
        if request['claims'].get('purpose') in ('agentmux-application-binding-request-v1',
                                               'agentmux-application-discovery-request-v1'):
            if self.application is None:
                raise ContractError('application_observation_unavailable')
            return await self.application.handle(request_bytes,
                discovery=request['claims']['purpose'] == 'agentmux-application-discovery-request-v1')
        if request['claims'].get('contractId') == 'identity-legacy-alias-resolve':
            return await self._resolve_legacy_alias(request_bytes, request)
        if request['claims'].get('contractId') == 'identity-application-account-resolve':
            return await self._resolve_application_account(request_bytes, request)
        if request['claims'].get('contractId') == 'identity-ordinary-secret-resolve':
            return await self._resolve_ordinary_secret(request_bytes, request)
        if request['claims'].get('contractId') == 'local-browser-session-open':
            return await self._open_local_browser(request_bytes, request)
        if request['claims'].get('contractId') in ('oidc-terminal-session-open',
                'oidc-terminal-session-status', 'oidc-terminal-session-close'):
            return await self._oidc_terminal_command(request_bytes, request)
        if request.get('claims', {}).get('contractId') not in IDENTITY_COMMANDS:
            raise ContractError('identity_transition_unsupported')
        # The cancellation identity is allocated by this owner, not supplied by
        # request JSON. Its stable operation ID permits exact retry reconciliation.
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.audit_envelope is None:
            raise ContractError('identity_actor_unverified')
        receipt = await self.owner.execute(admitted.audit_envelope)
        claims = {'purpose': 'agentmux-identity-receipt-v1', 'hubId': self._hub,
            'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer), 'requestDigest': payload_digest(request),
            'receipt': {'operationId': receipt.operation_id, 'decision': receipt.decision,
                        'reason': receipt.reason, 'entityVersion': receipt.entity_version,
                        'sequence': receipt.sequence, 'replayed': receipt.replayed}}
        response = {'schemaVersion': '1.0.0', 'claims': claims,
                    'signature': sign_claims(claims, self._seed)}
        validate('identity-command-receipt', response)
        return canonical_bytes(response)

    async def _oidc_terminal_command(self, request_bytes, request):
        """Run one fixed terminal operation for the signed enrolled caller."""
        contract = request['claims']['contractId']
        validate(contract, request['claims']['payload'])
        owner = self._oidc_terminal
        if owner is None or self.application is None:
            raise ContractError('oidc_terminal_unavailable')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('oidc_terminal_not_authorized')
        operation = strict_loads(admitted.decision.operation)
        caller, scope = operation['effectiveActorRef'], operation['scope']
        digest = payload_digest(request)
        async with self._oidc_terminal_lock:
            await self._prune_oidc_terminal(datetime.now(timezone.utc))
            return await self._execute_oidc_terminal(
                contract, request, admitted, caller, scope, digest)

    async def _execute_oidc_terminal(self, contract, request, admitted,
                                     caller, scope, digest):
        operation_id = request['claims']['operationId']
        owner = self._oidc_terminal
        cached = self._oidc_terminal_results.get(operation_id)
        if cached is not None:
            if cached[0] != digest:
                raise ContractError('oidc_terminal_unavailable')
            return cached[1]
        payload = request['claims']['payload']
        fields = {}
        cache = False
        if contract == 'oidc-terminal-session-open':
            if len(self._oidc_terminal_attempts) >= _MAX_OIDC_TERMINAL_ATTEMPTS:
                raise ContractError('oidc_terminal_unavailable')
            binding = await self.application.open_local_browser_binding(caller, scope)
            attempt = await owner.begin(binding)
            attempt_id = 'oidc_attempt_' + uuid.uuid4().hex
            self._oidc_terminal_attempts[attempt_id] = {
                'attempt': attempt, 'caller': caller, 'scope': scope,
                'sessionId': None, 'expiresAt': attempt.expires_at}
            fields = {'attemptId': attempt_id, 'userCode': attempt.user_code,
                'verificationUri': attempt.verification_uri, 'interval': attempt.interval,
                'expiresAt': attempt.expires_at.isoformat(
                    timespec='microseconds').replace('+00:00', 'Z')}
            cache = True
        elif contract == 'oidc-terminal-session-status':
            attempt_id = payload['attemptId']
            row = self._oidc_terminal_attempts.get(attempt_id)
            if (row is None or row['caller'] != caller or row['scope'] != scope):
                raise ContractError('oidc_terminal_unavailable')
            session_id = row['sessionId']
            if session_id is None:
                session = await owner.status(row['attempt'])
                if session is not None:
                    if len(self._oidc_terminal_sessions) >= _MAX_OIDC_TERMINAL_SESSIONS:
                        session.close()
                        self._oidc_terminal_attempts.pop(attempt_id, None)
                        raise ContractError('oidc_terminal_unavailable')
                    session_id = 'oidc_session_' + uuid.uuid4().hex
                    row['sessionId'] = session_id
                    self._oidc_terminal_sessions[session_id] = {
                        'session': session, 'caller': caller, 'scope': scope,
                        'expiresAt': session.expires_at}
            if session_id is None:
                fields = {'attemptId': attempt_id, 'outcome': 'pending',
                    'sessionId': None, 'sessionExpiresAt': None}
            else:
                session_row = self._oidc_terminal_sessions.get(session_id)
                if session_row is None:
                    raise ContractError('oidc_terminal_session_closed')
                session = session_row['session']
                fields = {'attemptId': attempt_id, 'outcome': 'approved',
                    'sessionId': session_id,
                    'sessionExpiresAt': session.expires_at.isoformat(
                        timespec='microseconds').replace('+00:00', 'Z')}
                cache = True
        else:
            session_id = payload['sessionId']
            row = self._oidc_terminal_sessions.get(session_id)
            if (row is None or row['caller'] != caller or row['scope'] != scope):
                raise ContractError('oidc_terminal_unavailable')
            row['session'].close()
            self._oidc_terminal_sessions.pop(session_id, None)
            for attempt_id, attempt_row in tuple(self._oidc_terminal_attempts.items()):
                if attempt_row['sessionId'] == session_id:
                    self._oidc_terminal_attempts.pop(attempt_id, None)
            fields = {'sessionId': session_id, 'outcome': 'closed'}
            cache = True
        try:
            response = self._oidc_terminal_response(
                contract, request, admitted.decision.valid_until, fields)
        except BaseException:
            if contract == 'oidc-terminal-session-open':
                row = self._oidc_terminal_attempts.pop(fields['attemptId'], None)
                if row is not None:
                    await owner.cancel(row['attempt'])
            raise
        if cache:
            if contract == 'oidc-terminal-session-open':
                retire_at = self._oidc_terminal_attempts[fields['attemptId']]['expiresAt']
            elif contract == 'oidc-terminal-session-status':
                retire_at = self._oidc_terminal_sessions[fields['sessionId']]['expiresAt']
            else:
                retire_at = datetime.now(timezone.utc) + timedelta(minutes=15)
            self._oidc_terminal_results[operation_id] = (digest, response, retire_at)
            while len(self._oidc_terminal_results) > _MAX_OIDC_TERMINAL_RESULTS:
                self._oidc_terminal_results.pop(next(iter(self._oidc_terminal_results)))
        return response

    async def _prune_oidc_terminal(self, now):
        for session_id, row in tuple(self._oidc_terminal_sessions.items()):
            if now >= row['expiresAt']:
                row['session'].close()
                self._oidc_terminal_sessions.pop(session_id, None)
        for attempt_id, row in tuple(self._oidc_terminal_attempts.items()):
            session_id = row['sessionId']
            if now < row['expiresAt'] and (session_id is None
                    or session_id in self._oidc_terminal_sessions):
                continue
            self._oidc_terminal_attempts.pop(attempt_id, None)
            if session_id is None:
                try:
                    await self._oidc_terminal.cancel(row['attempt'])
                except ContractError:
                    pass
        for operation_id, row in tuple(self._oidc_terminal_results.items()):
            if now >= row[2]:
                self._oidc_terminal_results.pop(operation_id, None)

    def _oidc_terminal_response(self, contract, request, authority_until, fields):
        issued = datetime.now(timezone.utc)
        request_until = datetime.fromisoformat(request['claims']['expiresAt'])
        valid_until = min(request_until,
                          authority_until if authority_until is not None else request_until)
        if issued >= valid_until:
            raise ContractError('oidc_terminal_unavailable')
        purposes = {
            'oidc-terminal-session-open': 'agentmux-oidc-terminal-session-open-response-v1',
            'oidc-terminal-session-status': 'agentmux-oidc-terminal-session-status-response-v1',
            'oidc-terminal-session-close': 'agentmux-oidc-terminal-session-close-response-v1'}
        claims = {'purpose': purposes[contract], 'hubId': self._hub,
            'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer),
            'requestDigest': payload_digest(request),
            'operationId': request['claims']['operationId'], **fields,
            'issuedAt': issued.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'validUntil': valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate(contract + '-response', response)
        return canonical_bytes(response)

    async def _open_local_browser(self, request_bytes, request):
        """Create browser authority only from this verified command and runtime."""
        validate('local-browser-session-open', request['claims']['payload'])
        host = self._local_browser_host
        if host is None or self.application is None:
            raise ContractError('local_browser_host_unavailable')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('local_browser_not_authorized')
        operation = strict_loads(admitted.decision.operation)
        caller, scope = operation['effectiveActorRef'], operation['scope']
        binding = await self.application.open_local_browser_binding(caller, scope)
        from .local_browser_session import LocalBrowserSession, LocalBrowserPairingAuthority
        session = await LocalBrowserSession.open_server_binding(binding, self.reader)
        payload = request['claims']['payload']
        try:
            # Binding and session setup may await current runtime state. Re-admit
            # the exact signed pairing command at the final approval boundary;
            # current application binding is not pairing authority.
            current_admission = await self.ingress.admit(request_bytes, cancellation_ref={
                'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
            if (current_admission.envelope is None
                    or current_admission.decision.outcome != 'allowed'
                    or current_admission.decision.operation != admitted.decision.operation):
                raise ContractError('local_browser_not_authorized')
            final_authority = LocalBrowserPairingAuthority._create(
                self.ingress, request_bytes,
                {'id': operation_id, 'ownerHubId': self._hub, 'revision': 1},
                admitted.decision.operation, caller, scope)
            await host.approve_local_browser(payload['challenge'], session, final_authority,
                                             origin=payload['origin'])
        except BaseException:
            session.close()
            raise
        current = await binding.current()
        issued = datetime.now(timezone.utc)
        valid_until = min(datetime.fromisoformat(request['claims']['expiresAt']),
                          datetime.fromisoformat(current['validUntil']))
        if issued >= valid_until:
            session.close()
            raise ContractError('local_browser_host_unavailable')
        claims = {'purpose': 'agentmux-local-browser-session-response-v1',
            'hubId': self._hub, 'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer), 'requestDigest': payload_digest(request),
            'operationId': operation_id,
            'challengeDigest': 'sha256:' + hashlib.sha256(
                payload['challenge'].encode('ascii')).hexdigest(),
            'callerRef': caller, 'scope': scope,
            'generation': current['generation'], 'lifetimeId': current['lifetimeId'],
            'authorityRef': current['authorityRef'],
            'authoritySequence': current['authoritySequence'], 'outcome': 'approved',
            'issuedAt': issued.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'validUntil': valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate('local-browser-session-response', response)
        return canonical_bytes(response)

    async def _resolve_legacy_alias(self, request_bytes, request):
        """Return a signed current binding without writing identity state."""
        from .legacy_identity import LegacyRegistration
        adapter = self._legacy_identity
        if adapter is None:
            raise ContractError('legacy_identity_unavailable')
        payload = request['claims']['payload']
        validate('identity-legacy-alias-resolve', payload)
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('legacy_identity_not_authorized')
        operation = strict_loads(admitted.decision.operation)
        if operation['scope'] != adapter.scope:
            raise ContractError('legacy_identity_scope_mismatch')
        if 'registrations' in payload:
            registrations = tuple(LegacyRegistration(
                row['requestedAddress'], row['canonicalSession'], row['registrationGeneration'],
                row['repository'], row['role'], row['agent'], row['state'], row['legacyAlias'])
                for row in payload['registrations'])
            bindings = await adapter.bind(registrations)
            selector = {'registrations': payload['registrations']}
        else:
            bindings = await adapter.bind((), remote_address=payload['remoteAddress'])
            if len(bindings) != 1 or bindings[0].local:
                raise ContractError('legacy_identity_resolution_invalid')
            selector = {'remoteAddress': payload['remoteAddress']}
        sequences = {binding.authority_sequence for binding in bindings}
        if sequences != {admitted.decision.authority_sequence}:
            # The grant and alias mapping must come from the same retained record.
            raise ContractError('legacy_identity_authority_changed')
        issued = datetime.now(timezone.utc)
        valid_until = admitted.decision.valid_until
        if valid_until is None or issued >= valid_until:
            raise ContractError('legacy_identity_authority_changed')
        claims = {'purpose': 'agentmux-legacy-alias-resolution-v1',
            'hubId': self._hub, 'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer), 'requestDigest': payload_digest(request),
            'operationId': operation_id, 'callerRef': operation['effectiveActorRef'],
            'scope': adapter.scope, **selector,
            'bindings': [binding.wire() for binding in bindings],
            'authoritySequence': admitted.decision.authority_sequence,
            'issuedAt': issued.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'validUntil': valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate('identity-legacy-alias-resolution', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('owner_body_limit')
        return encoded

    async def _resolve_application_account(self, request_bytes, request):
        """Return current public custody references without resolving secret bytes."""
        payload = request['claims']['payload']
        validate('identity-application-account-resolve', payload)
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('application_account_not_authorized')
        from .application_account import resolve_snapshot
        snapshot = await self.reader.current()
        issued = datetime.now(timezone.utc)
        resolved = resolve_snapshot(snapshot, admitted.envelope,
            audience={'hubId': self._hub, 'serviceId': 'identity-owner'}, now=issued)
        operation = strict_loads(admitted.decision.operation)
        claims = {'purpose': 'agentmux-application-account-resolution-v1',
            'hubId': self._hub, 'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer), 'requestDigest': payload_digest(request),
            'operationId': operation_id, 'callerRef': operation['effectiveActorRef'],
            'scope': resolved.scope, 'accountRef': resolved.account_ref,
            'accountPublicKey': resolved.account_public_key,
            'administratorIdentityRef': resolved.administrator_identity_ref,
            'administratorTransportRef': resolved.administrator_transport_ref,
            'administratorCredentialRef': resolved.administrator_credential_ref,
            'accountIssuerRef': resolved.account_issuer_ref,
            'authoritySequence': resolved.authority_sequence,
            'issuedAt': issued.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'validUntil': resolved.valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate('identity-application-account-resolution', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('owner_body_limit')
        return encoded

    async def _resolve_ordinary_secret(self, request_bytes, request):
        from .ordinary_secret import OrdinarySecretAuthority
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('ordinary_secret_not_authorized')
        resolved = await OrdinarySecretAuthority(self.reader).resolve(admitted.envelope)
        issued = datetime.now(timezone.utc)
        if issued >= resolved.valid_until:
            raise ContractError('ordinary_secret_not_authorized')
        claims = {'purpose': 'agentmux-ordinary-secret-resolution-v1',
            'hubId': self._hub, 'profileId': self._profile, 'authorityId': self._entity,
            'issuerRef': strict_loads(self._issuer), 'requestDigest': payload_digest(request),
            'operationId': operation_id, **resolved.claims(),
            'issuedAt': issued.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'validUntil': resolved.valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate('identity-ordinary-secret-resolution', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('owner_body_limit')
        return encoded

    async def _recover(self):
        async with self._recovery_lock:
            while not self._closed:
                progress = await self.ledger.prepare_history()
                if progress.ready:
                    return
                await asyncio.sleep(0)
            raise ContractError('identity_service_closed')

    def _checkpoint_if_due(self):
        if self._history is None or self._checkpoint_path is None:
            return
        if self._checkpoint_work is not None:
            if not self._checkpoint_work.done():
                return
            self._checkpoint_work.result()
        cursor = self._history.verified_cursor
        if self._cadence.due(cursor, time.monotonic()):
            self._checkpoint_work = asyncio.create_task(self._export_checkpoint(cursor))

    async def _export_checkpoint(self, cursor):
        prefix = Path(self._checkpoint_path)
        path = prefix.with_name(prefix.name + '.' + str(cursor) + '.' + uuid.uuid4().hex + '.json')
        digest = await export_verified_prefix(path, self._history, self._binding,
                                            self._stream_identity, cursor)
        await self._checkpoint_committed(CheckpointReceipt(str(path), digest, cursor))
        self._cadence.completed(cursor, time.monotonic())

    async def _checkpoint_loop(self):
        while not self._checkpoint_stop.is_set():
            try:
                await asyncio.wait_for(self._checkpoint_stop.wait(), 30)
            except asyncio.TimeoutError:
                self._checkpoint_if_due()

    async def start(self):
        async with self._lifecycle_lock:
            if self._closed or self._startup_task is not None:
                raise ContractError('identity_service_lifecycle')
            if self._history is None or self._checkpoint_path is None or not callable(self._checkpoint_committed) or self._backup is None:
                raise ContractError('identity_history_configuration_required')
            self._startup_task = asyncio.create_task(self._start_io())
        # Recovery can need many pages. Never hold the lifecycle lock while it
        # runs; close must be able to stop it and join this original task.
        await asyncio.shield(self._startup_task)

    async def _start_io(self):
        try:
            trusted = await self._backup.recovery_identity()
            self.ledger.require_recovery_identity(trusted)
            await self._recover()
            if self._closed:
                raise ContractError('identity_service_closed')
            await self._backup.start()
            if self._closed:
                raise ContractError('identity_service_closed')
            self._checkpoint_if_due()
            self._checkpoint_task = asyncio.create_task(self._checkpoint_loop())
            self._subscribe_task = asyncio.create_task(self._connection.subscribe(
                self._subject, cb=self._receive, pending_msgs_limit=32, pending_bytes_limit=32 * 65536))
            self._subscription = await asyncio.shield(self._subscribe_task)
            await asyncio.wait_for(self._connection.flush(), 3)
        except BaseException:
            self._closed = True
            raise

    async def _receive(self, message):
        if self._closed or not isinstance(message.reply, str) or not re.fullmatch(
                r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?', message.reply):
            return
        try:
            if len(message.data) > 65536:
                return
            request = strict_loads(message.data)
            if request.get('claims', {}).get('replySubject') != message.reply:
                return
        except Exception:
            return
        try:
            response = await asyncio.wait_for(self.handle(message.data), 10)
        except asyncio.CancelledError:
            raise
        except Exception:
            # A timeout may follow a commit. No new operation is allocated and
            # the reply never claims that the write was rejected or completed.
            response = canonical_bytes({'schemaVersion': '1.0.0',
                                        'error': 'identity_outcome_unconfirmed'})
        await self._connection.publish(message.reply, response)

    async def _drain(self):
        self._checkpoint_stop.set()
        try:
            if self._startup_task is not None:
                try:
                    await self._startup_task
                except Exception:
                    pass
            if self._subscription is None and self._subscribe_task is not None:
                try:
                    self._subscription = await self._subscribe_task
                except Exception:
                    # start already reported this terminal allocation failure.
                    # There is no returned subscription handle to drain.
                    pass
            if self._subscription is not None:
                await self._subscription.drain()
                self._subscription = None
        finally:
            if self._active:
                await asyncio.gather(*tuple(self._active), return_exceptions=True)
            try:
                if self._oidc_terminal is not None:
                    await self._oidc_terminal.close()
                if self._checkpoint_task is not None:
                    await self._checkpoint_task
            finally:
                try:
                    if self._checkpoint_work is not None:
                        await asyncio.shield(self._checkpoint_work)
                finally:
                    try:
                        if self._backup is not None:
                            await self._backup.close()
                    finally:
                        if self._history is not None:
                            self._history.close()

    async def close(self):
        async with self._lifecycle_lock:
            self._closed = True
            if (self._drain_task is None or (self._drain_task.done()
                    and not self._drain_task.cancelled() and self._drain_task.exception() is not None)):
                self._drain_task = asyncio.create_task(self._drain())
            # A timeout retains the original drain. Retrying close joins that
            # task rather than canceling it and losing ownership of callbacks.
            await asyncio.wait_for(asyncio.shield(self._drain_task), 10)


def verify_receipt(response_bytes, request_bytes, *, public_key, issuer_ref):
    """Verify a receipt against the exact request and a trusted enrolled key.

    This is an outcome receipt, never a reusable authorization grant. An unsigned
    failure means that the client must reconcile its original operation identity.
    """
    if type(response_bytes) is not bytes or len(response_bytes) > 65536:
        raise ContractError('identity_receipt_invalid')
    response, request = strict_loads(response_bytes), strict_loads(request_bytes)
    validate('identity-ingress-request', request)
    if set(response) != {'schemaVersion', 'claims', 'signature'} or response['schemaVersion'] != '1.0.0':
        raise ContractError('identity_outcome_unconfirmed')
    validate('identity-command-receipt', response)
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims.get('purpose') != 'agentmux-identity-receipt-v1'
            or claims.get('issuerRef') != issuer_ref
            or claims.get('requestDigest') != payload_digest(request)
            or any(claims.get(k) != request['claims'][k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('receipt', {}).get('operationId') != request['claims']['operationId']):
        raise ContractError('identity_receipt_binding')
    return strict_loads(canonical_bytes(claims['receipt']))
