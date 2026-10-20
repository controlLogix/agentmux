"""Retain one client connection through connect, invalidation and joined close.

The fixed production factory must validate credentials and strict local TLS
before constructing this owner. The owner signs queries with its enrolled key
and requires a current binding; it does not establish application readiness.
"""
import asyncio
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

from hub.client_launch_imports import use_bundled_sdk
use_bundled_sdk()

from agentmux_contracts import canonical_bytes, strict_loads

from hub.client_launch_binding import BindingError, ClientBindingState


class ConnectionFailure(RuntimeError):
    """Fixed public error retaining the original owner and private cause."""
    def __init__(self, code, owner, cause=None):
        super().__init__(code)
        self.owner = owner
        self._cause = cause

    def __repr__(self):
        return f'ConnectionFailure({str(self)!r})'


class MessageOutcomeUnconfirmed(ConnectionFailure):
    """The original exchange joined and its inbox retired on a healthy connection."""


class PolicyOutcomeUnconfirmed(ConnectionFailure):
    """The policy exchange joined; a fresh authorized read can reconcile it."""


def selected_publish_subjects(signer):
    """Return the enrolled identity routes and exact scoped integration pattern."""
    from identity.application_client import ApplicationClientKey
    if not isinstance(signer, ApplicationClientKey):
        raise ValueError('application_client_signer_required')
    selected = signer.selection
    identity = (f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
                f".identity.{selected['authorityId']}.command")
    subjects = [identity]
    if 'integrationEffectQuery' in selected:
        subjects.append(signer.command_subject('integration-effect-query'))
    commands = selected.get('integrationEffectCommands')
    if commands is not None:
        subjects.append(f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
                        ".integrations.*.command")
    if 'legacyAliasResolve' in selected:
        subject = signer.command_subject('identity-legacy-alias-resolve')
        if subject not in subjects:
            subjects.append(subject)
    if 'authoritySwitchRecovery' in selected:
        subjects.append(signer.command_subject('authority-switch'))
    if 'messageCommands' in selected:
        subjects.append(selected['messageCommands']['subject'])
    if 'knowledgeCommands' in selected and selected['knowledgeCommands']['subject'] not in subjects:
        subjects.append(selected['knowledgeCommands']['subject'])
    if 'codeCommands' in selected and selected['codeCommands']['subject'] not in subjects:
        subjects.append(selected['codeCommands']['subject'])
    if 'peerControlCommands' in selected and selected['peerControlCommands']['subject'] not in subjects:
        subjects.append(selected['peerControlCommands']['subject'])
    if 'federationPolicyCommands' in selected and selected['federationPolicyCommands']['subject'] not in subjects:
        subjects.append(selected['federationPolicyCommands']['subject'])
    if 'workCommands' in selected and selected['workCommands']['subject'] not in subjects:
        subjects.append(selected['workCommands']['subject'])
    return tuple(subjects)


class ClientConnectionOwner:
    """Use only on the creating event loop; never infer admission from this type.

    The production connection factory applies the shared credential and TLS
    guard. `_connect` is the internal lifecycle entry for that fixed factory,
    not a user-configurable connection API. Reconnect requires fresh admission;
    this owner never starts a replacement client or restores an old binding.
    """
    def __init__(self, client, binding, *, command_subject, reply_prefix, signer=None):
        if not isinstance(binding, ClientBindingState) or binding._connection is not client:
            raise ValueError('application_connection_binding_invalid')
        if (not isinstance(command_subject, str) or not re.fullmatch(
                r'amx\.v1\.h\.[a-z][a-z0-9_-]{0,95}\.o\.[a-z][a-z0-9_-]{0,95}'
                r'\.identity\.[a-z][a-z0-9_-]{0,95}\.command', command_subject)
                or not isinstance(reply_prefix, str)
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}', reply_prefix)):
            raise ValueError('application_connection_subject_invalid')
        self._publish_subjects = ((command_subject,) if signer is None else selected_publish_subjects(signer))
        if self._publish_subjects[0] != command_subject:
            raise ValueError('application_connection_subject_invalid')
        self._signer = signer
        self._command_request = None
        self._terminal_session_id = None
        self._binding_identity = None
        self._command_subject, self._reply_prefix = command_subject, reply_prefix
        self._loop = asyncio.get_running_loop()
        if getattr(client, '_agentmux_session', None) is not None:
            raise ValueError('application_connection_already_owned')
        self._client, self.binding = client, binding
        # Reuse the shared paired client's allocation-time ownership hook.
        self._client._agentmux_session = self
        self._connect_task = self._close_task = self._exchange_task = None
        self._subscriptions = {}
        self._authenticating = False
        self._closing = self._connected = False
        self._loss = object()

    def __repr__(self):
        return '<ClientConnectionOwner private>'

    def _terminal_claim(self):
        if self._signer is None or 'oidcTerminalSession' not in self._signer.selection:
            return {}
        if self._terminal_session_id is None:
            raise ConnectionFailure('oidc_terminal_session_required', self)
        return {'terminalSessionId': self._terminal_session_id}

    def _check_loop(self):
        if asyncio.get_running_loop() is not self._loop:
            raise ConnectionFailure('application_connection_owner_loop', self)

    def _remaining(self, deadline):
        self._check_loop()
        if type(deadline) not in (int, float) or not self._loop.time() < deadline < float('inf'):
            raise ConnectionFailure('application_connection_deadline', self)
        return deadline - self._loop.time()

    def _invalidate(self):
        self._connected = False
        self._loss = object()
        self.binding.invalidate()

    async def disconnected(self):
        self._check_loop()
        self._invalidate()

    async def reconnected(self):
        self._check_loop()
        self._invalidate()

    async def closed(self):
        self._check_loop()
        self._invalidate()

    async def error(self, _error):
        # Replace nats-py's default raw-error logger; callers receive fixed errors.
        self._check_loop()

    async def _connect(self, options, *, deadline, cleanup_deadline):
        self._check_loop()
        if self._closing or self._connect_task is not None:
            raise ConnectionFailure('application_connection_already_started', self)
        remaining = self._remaining(deadline)
        # These controls cannot be changed by enrollment or hook payloads.
        selected = dict(options, allow_reconnect=False, max_reconnect_attempts=1,
                        connect_timeout=min(remaining, 5), dont_randomize=True,
                        disconnected_cb=self.disconnected, reconnected_cb=self.reconnected,
                        closed_cb=self.closed, error_cb=self.error)
        loss = self._loss
        self._connect_task = asyncio.create_task(self._client.connect(**selected))
        try:
            done, _ = await asyncio.wait({self._connect_task}, timeout=self._remaining(deadline))
            if not done:
                raise TimeoutError()
            self._connect_task.result()
            if (self._closing or loss is not self._loss or self._client.is_connected is not True
                    or self._loop.time() >= deadline):
                raise ConnectionFailure('application_connection_unavailable', self)
            self._connected = True
        except BaseException as error:
            # close owns cancellation/join of the exact partially connected task.
            # If the caller is cancelled again, its exception still retains us.
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_connection_unavailable', self, error) from None
        return self

    def require_connection(self):
        self._check_loop()
        if self._closing or not self._connected or self._client.is_connected is not True:
            self._invalidate()
            raise ConnectionFailure('application_connection_unavailable', self)
        return self._client

    def check_open(self):
        self.require_connection()

    def own_subscription(self, subscription):
        # The shared paired client calls this before its SUB send can fail.
        self._check_loop()
        self._subscriptions.setdefault(id(subscription), [subscription, None])
        return subscription

    async def _retire_subscription(self, subscription):
        row = self._subscriptions[id(subscription)]
        if row[1] is None:
            row[1] = asyncio.create_task(subscription.unsubscribe())
            row[1].add_done_callback(lambda task: None if task.cancelled() else task.exception())
        await asyncio.shield(row[1])
        self._subscriptions.pop(id(subscription), None)

    async def _run_exchange(self, request_raw, reply_subject, deadline, subject, binding_epoch,
                            *, reply_limit=65536):
        client, loss = self.require_connection(), self._loss
        async with asyncio.timeout_at(deadline):
            subscription = await client.subscribe(reply_subject, pending_msgs_limit=1,
                                                  pending_bytes_limit=reply_limit)
            self.own_subscription(subscription)
            await client.flush(timeout=self._remaining(deadline))
            if loss is not self._loss:
                raise ConnectionFailure('application_connection_changed', self)
            self.require_connection()
            if binding_epoch is not None:
                self._require_query_binding(binding_epoch)
            if 'bindingComplete' in (getattr(self, '_storage_timing', None) or {}):
                self._capture_work_timing('publish', deadline)
            await client.publish(subject, request_raw, reply=reply_subject)
            await client.flush(timeout=self._remaining(deadline))
            message = await subscription.next_msg(timeout=self._remaining(deadline))
            if 'bindingComplete' in (getattr(self, '_storage_timing', None) or {}):
                self._capture_work_timing('replyReceived', deadline)
            if (loss is not self._loss or message.subject != reply_subject
                    or type(message.data) is not bytes or len(message.data) > reply_limit):
                raise ConnectionFailure('application_reply_refused', self)
            self.require_connection()
            await self._retire_subscription(subscription)
            if loss is not self._loss:
                raise ConnectionFailure('application_connection_changed', self)
            self.require_connection()
            return message.data

    async def exchange(self, request_raw, *, deadline, cleanup_deadline):
        return await self._exchange(request_raw, subject=self._command_subject,
            deadline=deadline, cleanup_deadline=cleanup_deadline)

    async def _exchange(self, request_raw, *, subject, deadline, cleanup_deadline, binding_epoch=None):
        self.require_connection()
        if subject not in self._publish_subjects:
            pattern = subject.rsplit('.', 2)[0] + '.*.command' if '.integrations.' in subject else None
            if (pattern not in self._publish_subjects or self._signer is None):
                raise ConnectionFailure('application_request_refused', self)
            try:
                self._signer.verify_command_request(request_raw, subject=subject)
            except BaseException:
                raise ConnectionFailure('application_request_refused', self) from None
        self._remaining(deadline)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            if type(request_raw) is not bytes or len(request_raw) > 1048576:
                raise ValueError()
            claims = strict_loads(request_raw)['claims']
            if len(request_raw) > 65536:
                from identity.authority import LEGACY_STORAGE_COMMANDS
                if claims['contractId'] not in LEGACY_STORAGE_COMMANDS or self._signer is None:
                    raise ValueError()
                self._signer.verify_command_request(request_raw, subject=subject)
                if getattr(self._client, 'max_payload', 0) < len(request_raw):
                    raise ValueError()
            reply_subject = claims['replySubject']
            suffix = reply_subject.removeprefix(self._reply_prefix + '.')
            if (not reply_subject.startswith(self._reply_prefix + '.')
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', suffix)):
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ConnectionFailure('application_request_refused', self) from None
        exchange = self._exchange_task = asyncio.create_task(
            self._run_exchange(request_raw, reply_subject, deadline, subject, binding_epoch))
        try:
            # wait retains the exact exchange task on caller cancellation.
            done, _ = await asyncio.wait({exchange}, timeout=self._remaining(deadline))
            if not done:
                raise TimeoutError()
            response = exchange.result()
            self._exchange_task = None
            return response
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_request_unconfirmed', self, error) from None

    @property
    def command_request(self):
        """Exact immutable request retained for the owning caller's reconciliation."""
        return self._command_request

    async def _exchange_message(self, request, *, subject, binding_epoch, deadline, cleanup_deadline):
        return await self._exchange_joined(request, subject=subject, binding_epoch=binding_epoch,
            deadline=deadline, cleanup_deadline=cleanup_deadline, policy=False)

    async def _exchange_policy(self, request, *, subject, binding_epoch, deadline, cleanup_deadline):
        return await self._exchange_joined(request, subject=subject, binding_epoch=binding_epoch,
            deadline=deadline, cleanup_deadline=cleanup_deadline, policy=True)

    async def _exchange_joined(self, request, *, subject, binding_epoch, deadline, cleanup_deadline, policy):
        self.require_connection()
        if self._signer is None or self._exchange_task is not None or subject not in self._publish_subjects:
            raise ConnectionFailure('application_request_refused', self)
        self._signer.verify_command_request(request, subject=subject)
        claims = strict_loads(request)['claims']
        from identity.authority import LEGACY_STORAGE_COMMANDS
        if policy:
            selected = self._signer.selection.get('federationPolicyCommands')
            if (selected is None or subject != selected['subject']
                    or claims['contractId'] not in ('configuration-read', 'configuration-set')
                    or len(request) > 65536):
                raise ConnectionFailure('application_request_refused', self)
        elif claims['contractId'] not in LEGACY_STORAGE_COMMANDS:
            raise ConnectionFailure('application_request_refused', self)
        reply = claims['replySubject']
        if (not reply.startswith(self._reply_prefix + '.')
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', reply.removeprefix(self._reply_prefix + '.'))
                or getattr(self._client, 'max_payload', 0) < len(request)):
            raise ConnectionFailure('application_request_refused', self)
        original_subscriptions, loss = set(self._subscriptions), self._loss
        # Only enrolled legacy storage uses 1 MiB frames. Policy keeps 64 KiB.
        exchange = self._exchange_task = asyncio.create_task(
            self._run_exchange(request, reply, deadline, subject, binding_epoch,
                               reply_limit=65536 if policy else 1048576))
        try:
            done, _ = await asyncio.wait({exchange}, timeout=self._remaining(deadline))
            if not done:
                raise TimeoutError()
            response = exchange.result()
            self._exchange_task = None
            return response
        except TimeoutError:
            # A timeout says nothing about the owner's effect. Retain the
            # original request, join its exact exchange and retire only its
            # inbox before permitting a fresh authorized outcome query.
            if not exchange.done():
                await asyncio.wait({exchange}, timeout=self._remaining(cleanup_deadline))
            if not exchange.done():
                raise ConnectionFailure('application_connection_cleanup_pending', self)
            if policy and (exchange.cancelled() or not isinstance(exchange.exception(), TimeoutError)):
                # The waiter's deadline is not the original exchange outcome.
                # A late invalid reply must keep the same terminal refusal.
                raise ConnectionFailure('application_policy_reply_unconfirmed', self)
            if not exchange.cancelled():
                exchange.exception()
            for identity in tuple(set(self._subscriptions) - original_subscriptions):
                subscription = self._subscriptions[identity][0]
                await asyncio.wait_for(self._retire_subscription(subscription),
                    timeout=self._remaining(cleanup_deadline))
            self.require_connection()
            if loss is not self._loss:
                raise ConnectionFailure('application_connection_changed', self)
            self._exchange_task = None
            if policy:
                raise PolicyOutcomeUnconfirmed('application_policy_outcome_unconfirmed', self) from None
            raise MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', self) from None

    def _require_query_binding(self, epoch=None):
        client = self.require_connection()
        if self._authenticating or (epoch is not None and epoch is not self.binding._epoch):
            raise ConnectionFailure('application_connection_changed', self)
        return self.binding.current(client, now=datetime.now(timezone.utc))

    async def _current_command_binding(self, *, deadline, cleanup_deadline, required_until=None):
        """Renew current authority once before a new command when needed."""
        try:
            observed = self._require_query_binding()
            if required_until is not None and datetime.fromisoformat(observed['validUntil']) < required_until:
                raise BindingError('application_binding_budget')
            return observed
        except BindingError:
            if self._signer is None or self._exchange_task is not None:
                raise
        await self.authenticate(self._signer, deadline=deadline, cleanup_deadline=cleanup_deadline)
        return self._require_query_binding()

    async def integration_command(self, *, contract_id, operation_id, expected_version, grant_ref,
                                  payload, approval_refs, deadline, cleanup_deadline):
        """Sign one enrolled integration command and retain its exact uncertain request."""
        self._remaining(deadline)
        selected = {} if self._signer is None else self._signer.selection
        commands = selected.get('integrationEffectCommands')
        if commands is None or contract_id not in commands['contracts']:
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            frozen = strict_loads(canonical_bytes({
                'grantRef': grant_ref, 'payload': payload, 'approvalRefs': approval_refs}))
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            original = operation_id if contract_id == 'integration-intent' else frozen['payload'][
                'originalOperationId']
            subject = self._signer.command_subject(contract_id, original)
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(60, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **self._terminal_claim(),
                **{key: selected[key] for key in ('hubId', 'profileId', 'authorityId')},
                'transportRef': commands['transportRef'], 'grantRef': frozen['grantRef'],
                'operationId': operation_id, 'expectedVersion': expected_version,
                'contractId': contract_id, 'approvalRefs': frozen['approvalRefs'],
                'payload': frozen['payload'],
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = self._signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            receipt = self._signer.verify_command_response(response, request, subject=subject)
            self._require_query_binding(epoch)
            self._remaining(deadline)
            return receipt
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    async def message_command(self, *, contract_id, operation_id, payload, expires_at,
                              deadline, cleanup_deadline, include_valid_until=False):
        """Use the protected message route and return only a verified owner receipt."""
        return await self._storage_command('messageCommands', contract_id=contract_id,
            operation_id=operation_id, payload=payload, expires_at=expires_at,
            deadline=deadline, cleanup_deadline=cleanup_deadline, include_valid_until=include_valid_until)

    async def knowledge_command(self, *, contract_id, operation_id, payload, expires_at,
                                deadline, cleanup_deadline):
        """Use the protected knowledge route and the same joined exchange."""
        return await self._storage_command('knowledgeCommands', contract_id=contract_id,
            operation_id=operation_id, payload=payload, expires_at=expires_at,
            deadline=deadline, cleanup_deadline=cleanup_deadline)

    async def code_command(self, *, contract_id, operation_id, payload, expires_at,
                           deadline, cleanup_deadline, include_valid_until=False):
        """Use only the protected code route and its joined storage exchange."""
        return await self._storage_command('codeCommands', contract_id=contract_id,
            operation_id=operation_id, payload=payload, expires_at=expires_at,
            deadline=deadline, cleanup_deadline=cleanup_deadline, include_valid_until=include_valid_until)

    async def work_command(self, *, contract_id, operation_id, payload, expires_at,
                           deadline, cleanup_deadline, include_valid_until=False, source_expectation=None):
        """Use the protected work route and retain the original joined exchange."""
        return await self._storage_command('workCommands', contract_id=contract_id,
            operation_id=operation_id, payload=payload, expires_at=expires_at,
            deadline=deadline, cleanup_deadline=cleanup_deadline, include_valid_until=include_valid_until,
            source_expectation=source_expectation)

    async def peer_control_command(self, *, contract_id, operation_id, payload, expires_at,
                                   approval_refs=(), deadline, cleanup_deadline):
        """Send one enrolled operator command without sharing peer credentials."""
        return await self._enrolled_owner_command('peerControlCommands', contract_id=contract_id,
            operation_id=operation_id, expected_version=payload['resourceRef']['revision'],
            payload=payload, expires_at=expires_at, approval_refs=approval_refs,
            deadline=deadline, cleanup_deadline=cleanup_deadline)

    async def federation_policy_command(self, *, contract_id, operation_id, expected_version,
                                        payload, expires_at, approval_refs=(), deadline, cleanup_deadline):
        """Use the separately enrolled policy owner and its bounded signed reply."""
        return await self._enrolled_owner_command('federationPolicyCommands', contract_id=contract_id,
            operation_id=operation_id, expected_version=expected_version, payload=payload,
            expires_at=expires_at, approval_refs=approval_refs, deadline=deadline,
            cleanup_deadline=cleanup_deadline)

    async def _enrolled_owner_command(self, field, *, contract_id, operation_id, expected_version,
                                      payload, expires_at, approval_refs, deadline, cleanup_deadline):
        self._remaining(deadline)
        selected = {} if self._signer is None else self._signer.selection
        route = selected.get(field)
        if route is None or contract_id not in route['grantRefs'] or self._exchange_task is not None:
            raise ConnectionFailure('application_command_unavailable', self)
        try:
            frozen = strict_loads(canonical_bytes({'payload': payload, 'approvalRefs': list(approval_refs)}))
            now = datetime.now(timezone.utc)
            requested_end = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                datetime.fromisoformat(expires_at))
            if requested_end <= now:
                raise ValueError()
            observed = await self._current_command_binding(deadline=deadline, cleanup_deadline=cleanup_deadline,
                required_until=requested_end)
            epoch = self.binding._epoch
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                datetime.fromisoformat(observed['validUntil']), datetime.fromisoformat(expires_at))
            if expiry <= now:
                raise ValueError()
            claims = {'purpose': 'agentmux-client-possession-v1', **self._terminal_claim(),
                **{k: selected[k] for k in ('hubId', 'profileId', 'authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': expected_version,
                'contractId': contract_id, 'payload': frozen['payload'], 'approvalRefs': frozen['approvalRefs'],
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            subject = self._signer.command_subject(contract_id)
            request = self._signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            exchange = self._exchange_policy if field == 'federationPolicyCommands' else self._exchange
            response = await exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            receipt = self._signer.verify_command_response(response, request, subject=subject)
            self._require_query_binding(epoch)
            self._remaining(deadline)
            return receipt
        except PolicyOutcomeUnconfirmed:
            raise
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    def _capture_work_timing(self, stage, deadline):
        try:
            timing = getattr(self, '_storage_timing', None)
            if timing is not None:
                now = time.monotonic()
                timing[stage] = {'at': now, 'remaining': deadline - now}
        except BaseException:
            pass

    async def _storage_command(self, field, *, contract_id, operation_id, payload, expires_at,
                               deadline, cleanup_deadline, include_valid_until=False, source_expectation=None):
        self._remaining(deadline)
        from identity.work_client import WORK_COMMANDS
        if source_expectation is not None and (field != 'workCommands' or contract_id not in WORK_COMMANDS):
            raise ConnectionFailure('application_command_unavailable', self)
        if (include_valid_until and not (field == 'workCommands' and contract_id in WORK_COMMANDS)
                and (field, contract_id) not in (
                ('codeCommands', 'federation-code-outcome'), ('codeCommands', 'federation-code-read'),
                ('messageCommands', 'federation-message-outcome'))):
            raise ConnectionFailure('application_command_unavailable', self)
        selected = {} if self._signer is None else self._signer.selection
        route = selected.get(field)
        if route is None or contract_id not in route['grantRefs'] or self._exchange_task is not None:
            raise ConnectionFailure('application_command_unavailable', self)
        timing = ({'contract': contract_id} if field == 'workCommands' and contract_id in (
            'federation-work-inspect', 'federation-work-register',
            'federation-work-state', 'federation-work-outcome') else None)
        self._storage_timing = timing
        try:
            frozen = strict_loads(canonical_bytes(payload))
            now = datetime.now(timezone.utc)
            requested_end = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                datetime.fromisoformat(expires_at))
            if requested_end <= now:
                raise ValueError()
            prior_epoch = self.binding._epoch
            self._capture_work_timing('bindingStart', deadline)
            observed = await self._current_command_binding(deadline=deadline, cleanup_deadline=cleanup_deadline,
                required_until=requested_end)
            self._capture_work_timing('bindingComplete', deadline)
            if timing is not None:
                timing['bindingRefreshed'] = prior_epoch is not self.binding._epoch
            epoch = self.binding._epoch
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                datetime.fromisoformat(observed['validUntil']), datetime.fromisoformat(expires_at))
            if expiry <= now:
                raise ValueError()
            claims = {'purpose': 'agentmux-client-possession-v1', **self._terminal_claim(),
                **{k: selected[k] for k in ('hubId', 'profileId', 'authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': frozen['resourceRef']['revision'],
                'contractId': contract_id, 'payload': frozen, 'approvalRefs': [],
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            if source_expectation is not None:
                claims['workSource'] = strict_loads(canonical_bytes(source_expectation))
            subject = self._signer.command_subject(contract_id)
            request = self._signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            self._capture_work_timing('exchangeStart', deadline)
            response = await self._exchange_message(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            receipt = self._signer.verify_command_response(response, request, subject=subject,
                **({'include_valid_until': True} if include_valid_until else {}))
            self._require_query_binding(epoch)
            try:
                self._remaining(deadline)
            except ConnectionFailure as error:
                if (field != 'workCommands' or contract_id not in WORK_COMMANDS
                        or type(error) is not ConnectionFailure
                        or str(error) != 'application_connection_deadline'
                        or self._exchange_task is not None):
                    raise
                # The verified exchange has joined and retired its inbox.
                # Refuse the late result, but retain the healthy connection for
                # a fresh authorized query of the original operation.
                self.require_connection()
                raise MessageOutcomeUnconfirmed(
                    'application_message_outcome_unconfirmed', self, error) from None
            return receipt
        except MessageOutcomeUnconfirmed as error:
            self._capture_work_timing('exchangeJoined', deadline)
            if timing is not None:
                error._storage_command_timing = timing
            raise
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            failure = ConnectionFailure('application_command_unconfirmed', self, error)
            self._capture_work_timing('exchangeJoined', deadline)
            if timing is not None:
                failure._storage_command_timing = timing
            raise failure from None
        finally:
            self._storage_timing = None

    async def query_integration_effect(self, *, operation_id, expected_version, deadline, cleanup_deadline):
        """Use the enrolled query route on this currently bound connection only."""
        self._remaining(deadline)
        if self._signer is None or 'integrationEffectQuery' not in self._signer.selection:
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            signer, selected = self._signer, self._signer.selection
            query = selected['integrationEffectQuery']
            subject = signer.command_subject('integration-effect-query')
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(60, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **self._terminal_claim(),
                **{k: selected[k] for k in ('hubId', 'profileId', 'authorityId')},
                'transportRef': query['transportRef'], 'grantRef': query['grantRef'],
                'operationId': operation_id, 'expectedVersion': expected_version,
                'contractId': 'integration-effect-query', 'approvalRefs': [],
                'payload': {'effectRef': {'id': subject.split('.')[-2], 'ownerHubId': selected['hubId'],
                                         'revision': expected_version},
                    'originalOperationId': query['originalOperationId'],
                    'originalPayloadDigest': query['originalPayloadDigest']},
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            receipt = signer.verify_command_response(response, request, subject=subject)
            self._require_query_binding(epoch)
            self._remaining(deadline)
            return receipt
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    async def query_legacy_aliases(self, *, registrations=None, remote_address=None,
                                   operation_id, deadline, cleanup_deadline):
        """Resolve one explicit local or remote selector on the bound identity route."""
        self._remaining(deadline)
        if self._signer is None or 'legacyAliasResolve' not in self._signer.selection:
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            if (registrations is None) == (remote_address is None):
                raise ValueError()
            selector = ({'registrations': registrations} if remote_address is None
                        else {'remoteAddress': remote_address})
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            signer, selected = self._signer, self._signer.selection
            query = selected['legacyAliasResolve']
            subject = signer.command_subject('identity-legacy-alias-resolve')
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(60, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **self._terminal_claim(),
                **{k: selected[k] for k in ('hubId', 'profileId', 'authorityId')},
                'transportRef': query['transportRef'], 'grantRef': query['grantRef'],
                'operationId': operation_id, 'expectedVersion': 0,
                'contractId': 'identity-legacy-alias-resolve', 'approvalRefs': [],
                'payload': {'authorityId': selected['authorityId'], **selector},
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            resolution = signer.verify_command_response(response, request, subject=subject,
                now=datetime.now(timezone.utc))
            current = self._require_query_binding(epoch)
            if any(binding.authority_sequence < current['authoritySequence']
                    or strict_loads(binding.instance_owner) is not None
                    or binding.local != (remote_address is None)
                    for binding in resolution.bindings):
                raise ValueError()
            self._remaining(deadline)
            return resolution
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    async def authority_switch_recovery(self, *, operation_id, deadline, cleanup_deadline):
        """Request one exact pre-cutover recovery from the enrolled owner route."""
        self._remaining(deadline)
        if self._signer is None or 'authoritySwitchRecovery' not in self._signer.selection:
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            signer, selection = self._signer, self._signer.selection
            route = selection['authoritySwitchRecovery']
            subject = signer.command_subject('authority-switch')
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **self._terminal_claim(),
                **{key: selection[key] for key in ('hubId', 'profileId', 'authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRef'],
                'operationId': operation_id, 'expectedVersion': 1,
                'contractId': 'authority-switch', 'approvalRefs': [],
                'payload': {'action': 'request-recovery', 'switchId': route['switchId'],
                            'source': route['source']},
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            authorization = signer.verify_command_response(
                response, request, subject=subject, now=datetime.now(timezone.utc))
            self._require_query_binding(epoch)
            if (datetime.now(timezone.utc) >= authorization._valid_until
                    or authorization._seal is not signer._authority_switch_seal):
                raise ValueError()
            self._remaining(deadline)
            return authorization
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure(
                    'application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    async def local_browser_session_open(self, *, challenge, origin, operation_id,
                                         deadline, cleanup_deadline):
        """Approve one pending browser challenge through the enrolled identity route."""
        self._remaining(deadline)
        if self._signer is None or 'localBrowserSessionOpen' not in self._signer.selection:
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            signer, selected = self._signer, self._signer.selection
            command = selected['localBrowserSessionOpen']
            subject = signer.command_subject('local-browser-session-open')
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(5, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{key: selected[key] for key in ('hubId', 'profileId', 'authorityId')},
                'transportRef': command['transportRef'], 'grantRef': command['grantRef'],
                'operationId': operation_id, 'expectedVersion': 0,
                'contractId': 'local-browser-session-open', 'approvalRefs': [],
                'payload': {'challenge': challenge, 'origin': origin},
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            current = self._require_query_binding(epoch)
            result = signer.verify_command_response(response, request, subject=subject,
                now=datetime.now(timezone.utc))
            current = self._require_query_binding(epoch)
            if (result['generation'] != current['generation']
                    or result['lifetimeId'] != current['lifetimeId']
                    or result['authoritySequence'] < current['authoritySequence']
                    or result['authorityRef'] != current['authorityRef']):
                raise ValueError()
            self._remaining(deadline)
            return result
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    async def oidc_terminal_command(self, *, contract_id, payload, operation_id,
                                    deadline, cleanup_deadline):
        """Run one fixed terminal session command on the retained identity route."""
        self._remaining(deadline)
        if (self._signer is None or 'oidcTerminalSession' not in self._signer.selection
                or contract_id not in ('oidc-terminal-session-open',
                                       'oidc-terminal-session-status',
                                       'oidc-terminal-session-close')):
            raise ConnectionFailure('application_command_unavailable', self)
        if self._exchange_task is not None:
            raise ConnectionFailure('application_request_in_progress', self)
        try:
            observed = await self._current_command_binding(
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            epoch = self.binding._epoch
            signer, selected = self._signer, self._signer.selection
            command = selected['oidcTerminalSession']
            subject = signer.command_subject(contract_id)
            now = datetime.now(timezone.utc)
            expiry = min(now + timedelta(seconds=min(10, self._remaining(deadline))),
                         datetime.fromisoformat(observed['validUntil']))
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{key: selected[key] for key in ('hubId', 'profileId', 'authorityId')},
                'transportRef': command['transportRef'],
                'grantRef': command['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': 0,
                'contractId': contract_id, 'approvalRefs': [], 'payload': payload,
                'replySubject': self._reply_prefix + '.' + secrets.token_hex(16),
                'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'expiresAt': expiry.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
            request = signer.sign_command(claims, subject=subject, now=now)
            self._command_request = request
            response = await self._exchange(request, subject=subject, binding_epoch=epoch,
                deadline=deadline, cleanup_deadline=cleanup_deadline)
            self._require_query_binding(epoch)
            result = signer.verify_command_response(
                response, request, subject=subject, now=datetime.now(timezone.utc))
            self._require_query_binding(epoch)
            if contract_id == 'oidc-terminal-session-status' and result['outcome'] == 'approved':
                self._terminal_session_id = result['sessionId']
            elif contract_id == 'oidc-terminal-session-close':
                self._terminal_session_id = None
            self._remaining(deadline)
            return result
        except BaseException as error:
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure(
                    'application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_command_unconfirmed', self, error) from None

    def _claims(self, selection, purpose, deadline):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=min(5, self._remaining(deadline)))
        claims = {key: selection[key] for key in (
            'hubId', 'profileId', 'authorityId', 'instanceId', 'releaseDigest',
            'policyRef', 'workspaceRef', 'transportRef', 'grantRef')}
        claims.update(purpose=purpose, requestId='client_' + secrets.token_hex(16), nonce=secrets.token_hex(32),
            replySubject=self._reply_prefix + '.' + secrets.token_hex(16),
            issuedAt=now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            expiresAt=expires.isoformat(timespec='microseconds').replace('+00:00', 'Z'))
        return claims

    async def authenticate(self, signer, *, deadline, cleanup_deadline):
        """Discover then bind with the actual enrolled client-purpose signer.

        A bound result is not a blanket domain authorization or readiness claim.
        No transport, signer or runtime tuple is taken from a tool request.
        """
        from identity.application_client import ApplicationClientKey
        self.require_connection()
        if self._authenticating:
            raise ConnectionFailure('application_request_in_progress', self)
        self._authenticating = True
        self.binding.invalidate()
        loss = self._loss
        try:
            if not isinstance(signer, ApplicationClientKey):
                raise ValueError()
            selection = signer.selection
            expected_subject = (f"amx.v1.h.{selection['hubId']}.o.{selection['scope']['organizationId']}"
                                f".identity.{selection['authorityId']}.command")
            if (expected_subject != self._command_subject
                    or selection['replyIssuerPublicKey'] != self.binding._public_key
                    or selection['replyIssuerRef'] != self.binding._signing_key_ref
                    or selection['callerRef'] != self.binding._caller_ref
                    or selection['scope'] != self.binding._scope):
                raise ValueError()
            request = signer.sign_discovery(self._claims(selection,
                'agentmux-application-discovery-request-v1', deadline))
            reply = await self.exchange(request, deadline=deadline, cleanup_deadline=cleanup_deadline)
            observed = signer.verify_response(reply, request, now=datetime.now(timezone.utc))
            identity = (observed['generation'], observed['lifetimeId'])
            if self._binding_identity is not None and identity != self._binding_identity:
                raise ValueError()
            if loss is not self._loss:
                raise ValueError()
            self.require_connection()
            claims = self._claims(selection, 'agentmux-application-binding-request-v1', deadline)
            claims.update(generation=observed['generation'], lifetimeId=observed['lifetimeId'])
            request = signer.sign_binding(claims)
            attempt = self.binding.begin(self.require_connection(), request)
            reply = await self.exchange(request, deadline=deadline, cleanup_deadline=cleanup_deadline)
            if loss is not self._loss:
                raise ValueError()
            bound = self.binding.accept(self.require_connection(), attempt, reply,
                                        now=datetime.now(timezone.utc))
            if (bound['generation'], bound['lifetimeId']) != identity:
                raise ValueError()
            self._binding_identity = identity
            return bound
        except BaseException as error:
            self.binding.invalidate()
            try:
                await self.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', self, cleanup) from None
            raise ConnectionFailure('application_binding_unavailable', self, error) from None
        finally:
            self._authenticating = False

    async def _finish_close(self):
        # Connection setup must join before close, so it cannot allocate a new
        # transport after the original close has run.
        if self._connect_task is not None:
            if not self._connect_task.done():
                self._connect_task.cancel()
            try:
                await self._connect_task
            except BaseException:
                pass  # Setup failure was reported; its partial client is still owned.
        if self._exchange_task is not None:
            if not self._exchange_task.done():
                self._exchange_task.cancel()
            try:
                await self._exchange_task
            except BaseException:
                pass  # Request failure does not establish its outcome.
        failures = []
        try:
            for subscription, _task in list(self._subscriptions.values()):
                try:
                    await self._retire_subscription(subscription)
                except BaseException as error:
                    failures.append(error)
        finally:
            await self._client.close()
        if failures:
            raise BaseExceptionGroup('private client subscription cleanup', failures)

    async def close(self, *, deadline):
        self._check_loop()
        if not self._closing:
            self._closing = True
            self._invalidate()
            self.binding.close()
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._finish_close())
            # Retrieve the outcome even if a timed-out/cancelled caller leaves.
            # The exact task and its failure remain retained for the next join.
            self._close_task.add_done_callback(
                lambda task: None if task.cancelled() else task.exception())
        try:
            if not self._close_task.done():
                await asyncio.wait({self._close_task}, timeout=self._remaining(deadline))
            if not self._close_task.done():
                raise TimeoutError()
            self._close_task.result()
        except BaseException as error:
            # A closed flag or another no-op close cannot prove a consumed failed
            # close succeeded. Repeated calls join only this original task.
            raise ConnectionFailure('application_connection_cleanup_pending', self, error) from None


def _new_connection_owner(signer, *, reply_prefix, leaf_certificate_sha256=None):
    """Allocate the fixed paired client; credential/TLS admission must precede connect."""
    from identity.application_client import ApplicationClientKey
    from hub.nats_transport import new_client
    if not isinstance(signer, ApplicationClientKey):
        raise ValueError('application_client_signer_required')
    selected = signer.selection
    subject = (f"amx.v1.h.{selected['hubId']}.o.{selected['scope']['organizationId']}"
               f".identity.{selected['authorityId']}.command")
    client = (new_client(require_tls=True) if leaf_certificate_sha256 is None else
              new_client(require_tls=True, leaf_certificate_sha256=leaf_certificate_sha256))
    binding = ClientBindingState(client, public_key=selected['replyIssuerPublicKey'],
        signing_key_ref=selected['replyIssuerRef'], caller_ref=selected['callerRef'], scope=selected['scope'])
    return ClientConnectionOwner(client, binding, command_subject=subject, reply_prefix=reply_prefix, signer=signer)
