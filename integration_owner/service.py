"""Receive enrolled external-effect commands on exact project effect routes.

The host supplies its scoped connection and actual authority, ledger and artifacts.
No HTTP actor label, filesystem fence or response receipt grants permission.
"""
import asyncio
from dataclasses import dataclass
import inspect
from pathlib import Path
import re
import time
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.ingress import EnrolledIngress
from identity.authority import AuthorityReader, LedgerAuthorityReader, evaluate_snapshot, _active, _indexes, _key, _utc_now
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
from state_owner.backup_lifecycle import OwnerBackupLifecycle
from .intent import effect_id, intent, query, reference
from .receiver import IntegrationOwner
from .receipts import COMMANDS, _validate_receipt, verify_possession, verify_receipt
from state_owner.checkpoints import CheckpointCadence, export_checkpoint_async



@dataclass(frozen=True, repr=False)
class CheckpointReceipt:
    manifest_path: str
    digest: str
    cursor: int


class IntegrationService:
    def __init__(self, connection, owner, ingress, *, checkpoint_path, checkpoint_committed,
                 backup_lifecycle=None):
        if (not isinstance(owner, IntegrationOwner) or not isinstance(ingress, EnrolledIngress)
                or ingress._reader is not owner._authority
                or backup_lifecycle is not None
                and not isinstance(backup_lifecycle, OwnerBackupLifecycle)):
            raise ContractError('integration_service_configuration')
        self.owner, self.ingress = owner, ingress
        self.ledger = owner._ledger
        self._binding = owner._binding
        self._history = self.ledger._history
        self._stream_identity = self.ledger._identity
        self._checkpoint_path, self._checkpoint_committed = checkpoint_path, checkpoint_committed
        self._backup_lifecycle = backup_lifecycle
        self._hub, self._entity, self._profile = (owner._authority._hub, owner._authority._entity,
                                                 owner._authority._profile)
        if self._hub != self._binding.hub_id:
            raise ContractError('integration_service_configuration')
        organization = strict_loads(self._binding.scope)['organizationId']
        self._subject = '.'.join(('amx', 'v1', 'h', self._hub, 'o', organization,
                                  'integrations', self._binding.entity_id, 'command'))
        self._seed, self._issuer = ingress._seed, ingress._issuer_ref
        self._connection = connection
        self._cadence = CheckpointCadence(now=time.monotonic())
        self._checkpoint_task = self._checkpoint_work = None
        self._checkpoint_stop = asyncio.Event()
        self._recovery_lock = asyncio.Lock()
        self._subscription = self._subscribe_task = self._startup_task = self._drain_task = None
        self._closed, self._ready = False, False
        self._lifecycle_lock = asyncio.Lock()
        self._active = set()
        self._callbacks = set()

    @classmethod
    def from_enrolled_host(cls, connection, *, authority, binding, provider, credential_ref,
                           stream, stream_identity, retention, history, artifacts,
                           issuer_ref, signing_seed, checkpoint_path, checkpoint_committed,
                           credentials=None, jetstream_domain=None, backup_lifecycle=None,
                           session_authorizer=None):
        """Compose only explicit host-enrolled resources; never create a stream.

        The host owns credentials, stream identity, history, artifacts and the
        checkpoint commit handler. Start before advertising the route, and close
        before releasing its connection. A provider config pin must survive
        restart; this constructor never enrolls or changes it.
        """
        if not isinstance(authority, LedgerAuthorityReader):
            raise ContractError('integration_enrolled_authority_required')
        if (jetstream_domain is not None and (type(jetstream_domain) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', jetstream_domain))):
            raise ContractError('integration_jetstream_domain_invalid')
        jetstream = (connection.jetstream() if jetstream_domain is None else
                     connection.jetstream(domain=jetstream_domain))
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding),
            binding=binding, retention=retention, stream_identity=stream_identity,
            history=history, require_completion_budget=True)
        owner = IntegrationOwner(authority, ledger, binding, provider=provider,
            credential_ref=credential_ref, artifacts=artifacts, credentials=credentials)
        ingress = EnrolledIngress(authority, issuer_ref=issuer_ref, signing_seed=signing_seed,
                                  session_authorizer=session_authorizer)
        return cls(connection, owner, ingress, checkpoint_path=checkpoint_path,
                   checkpoint_committed=checkpoint_committed,
                   backup_lifecycle=backup_lifecycle)

    def __repr__(self):
        return '<IntegrationService private>'

    @property
    def subject(self):
        return self._subject

    def check_health(self):
        if self._closed or not self._ready:
            raise ContractError('integration_service_unavailable')
        for task in (self._startup_task, self._checkpoint_work, self._checkpoint_task):
            if task is not None and task.done():
                task.result()
        if self._backup_lifecycle is not None:
            self._backup_lifecycle.check()

    async def handle(self, request_bytes):
        self.check_health()
        if len(self._active) >= 32:
            raise ContractError('integration_service_busy')
        completed = asyncio.get_running_loop().create_future()
        self._active.add(completed)
        try:
            await self._recover()
            response = await self._handle(request_bytes)
            self._checkpoint_if_due()
            return response
        finally:
            self._active.discard(completed)
            completed.set_result(None)

    async def _handle(self, request_bytes):
        if type(request_bytes) is not bytes or len(request_bytes) > 65536:
            raise ContractError('owner_body_limit')
        request = strict_loads(request_bytes)
        validate('identity-ingress-request', request)
        if request['claims']['contractId'] not in COMMANDS:
            raise ContractError('integration_command_unsupported')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('integration_not_authorized')
        receipt = await self.owner.handle(admitted.envelope)
        await self._verify_enrollment(admitted.envelope)
        claims = {'purpose': 'agentmux-integration-command-receipt-v1', 'hubId': self._hub,
            'profileId': self._profile, 'authorityId': self._entity, 'issuerRef': strict_loads(self._issuer),
            'requestDigest': payload_digest(request), 'receipt': receipt.wire_payload()}
        response = {'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, self._seed)}
        _validate_receipt(response)
        return canonical_bytes(response)

    async def _verify_enrollment(self, admitted=None):
        # This final snapshot supplies both signer and caller checks. Do not
        # await another authority read between these checks and reply signing.
        snapshot = await self.owner._authority.current()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._hub)
        now = _utc_now()
        issuer = index['issuers'].get(_key(strict_loads(self._issuer)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or identity is None
                or identity['kind'] != 'service' or not _active(identity, now)):
            raise ContractError('integration_issuer_unavailable')
        challenge = {'purpose': 'agentmux-integration-host-key-check-v1',
                     'hubId': self._hub, 'effectId': self._binding.entity_id}
        verify_possession(challenge, sign_claims(challenge, self._seed), issuer['publicKey'])
        if admitted is not None:
            envelope = strict_loads(admitted)
            operation = envelope['operation']
            decision = evaluate_snapshot(snapshot, admitted,
                audience={'hubId': self._hub, 'serviceId': 'integration-owner'}, now=now)
            if (self._closed or self.owner._closed or decision.outcome != 'allowed'
                    or decision.audit_actor is None or decision.operation != canonical_bytes(operation)
                    or decision.valid_until is None or decision.valid_until <= now
                    or canonical_bytes(operation['scope']) != self._binding.scope):
                raise ContractError('integration_access_refused')
            await self.ingress.authorize_terminal(operation)
            if (envelope['contractId'] in ('integration-intent', 'integration-attempt-start')
                    and not operation['approvalRefs']):
                raise ContractError('integration_approval_required')
            if asyncio.current_task().cancelling():
                raise asyncio.CancelledError()

    async def _recover(self):
        async with self._recovery_lock:
            while not self._closed:
                progress = await self.ledger.prepare_history()
                if progress.ready:
                    return
                await asyncio.sleep(0)
            raise ContractError('integration_service_closed')

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
        digest = await export_checkpoint_async(path, self._history, self._binding,
                                               self._stream_identity, through=cursor)
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
                raise ContractError('integration_service_lifecycle')
            if (self._history is None or not self.ledger.completion_budget_required
                    or self._checkpoint_path is None or not callable(self._checkpoint_committed)):
                raise ContractError('integration_history_configuration_required')
            self._startup_task = asyncio.create_task(self._start_io(subscribe=True))
        # Recovery can need many pages. Never hold the lifecycle lock while it
        # runs; close must be able to stop it and join this original task.
        await asyncio.shield(self._startup_task)

    async def start_embedded(self):
        """Recover one exact owner for an enrolled router without subscribing."""
        async with self._lifecycle_lock:
            if self._closed or self._startup_task is not None:
                raise ContractError('integration_service_lifecycle')
            if (self._history is None or not self.ledger.completion_budget_required
                    or self._checkpoint_path is None or not callable(self._checkpoint_committed)):
                raise ContractError('integration_history_configuration_required')
            self._startup_task = asyncio.create_task(self._start_io(subscribe=False))
        await asyncio.shield(self._startup_task)

    async def _start_io(self, *, subscribe):
        try:
            if self._backup_lifecycle is not None:
                self.ledger.require_recovery_identity(
                    await self._backup_lifecycle.recovery_identity())
            await self._recover()
            if self._closed:
                raise ContractError('integration_service_closed')
            await self._verify_enrollment()
            if self._closed:
                raise ContractError('integration_service_closed')
            self._ready = True
            self._checkpoint_if_due()
            self._checkpoint_task = asyncio.create_task(self._checkpoint_loop())
            if self._backup_lifecycle is not None:
                await self._backup_lifecycle.start()
            if subscribe:
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
        if len(self._callbacks) >= 32:
            return
        # Keep the original reply task if NATS cancels its callback while a
        # commit or publish is pending. Close joins this task before the host
        # releases the connection, worker or history.
        task = asyncio.create_task(self._respond(message))
        self._callbacks.add(task)
        task.add_done_callback(self._reply_finished)
        await asyncio.shield(task)

    def _reply_finished(self, task):
        self._callbacks.discard(task)
        if not task.cancelled():
            task.exception()

    async def _respond(self, message):
        try:
            response = await asyncio.wait_for(self.handle(message.data), 10)
        except asyncio.CancelledError:
            raise
        except Exception:
            # A timeout may follow a commit. Preserve the original operation
            # identity so the client can reconcile its uncertain outcome.
            response = canonical_bytes({'schemaVersion': '1.0.0',
                                        'error': 'integration_outcome_unconfirmed'})
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
            if self._callbacks:
                await asyncio.gather(*tuple(self._callbacks), return_exceptions=True)
            if self._active:
                await asyncio.gather(*tuple(self._active), return_exceptions=True)
            try:
                if self._checkpoint_task is not None:
                    await self._checkpoint_task
            finally:
                try:
                    if self._checkpoint_work is not None:
                        await asyncio.shield(self._checkpoint_work)
                finally:
                    # Keep private history open if the original worker cannot
                    # yet be joined. A later close retries that owned cleanup.
                    backup_error = None
                    if self._backup_lifecycle is not None:
                        try:
                            await self._backup_lifecycle.close()
                        except BaseException as error:
                            backup_error = error
                    try:
                        await self.owner.close()
                    finally:
                        if self._history is not None:
                            self._history.close()
                    if backup_error is not None:
                        raise backup_error

    async def close(self):
        async with self._lifecycle_lock:
            self._closed = True
            if (self._drain_task is None or (self._drain_task.done()
                    and not self._drain_task.cancelled() and self._drain_task.exception() is not None)):
                self._drain_task = asyncio.create_task(self._drain())
            # A timeout retains the original drain. Retrying close joins that
            # task rather than canceling it and losing ownership of callbacks.
            await asyncio.wait_for(asyncio.shield(self._drain_task), 10)


class IntegrationRouterService:
    """Route one enrolled provider and project to separately retained effect owners.

    The wildcard subscription is only broker routing. The router first performs
    normal current ingress admission, derives the exact effect identity from the
    admitted operation, and then delegates to an exact IntegrationService which
    repeats ingress, approval and current-authority checks before any owner work.
    """

    def __init__(self, connection, ingress, *, scope, provider, credential_ref,
                 service_factory, artifacts=None, credentials=None):
        if (not isinstance(ingress, EnrolledIngress)
                or not isinstance(ingress._reader, AuthorityReader)
                or provider not in ('github', 'jira', 'confluence')
                or not callable(service_factory)):
            raise ContractError('integration_router_configuration')
        try:
            enrolled_scope = strict_loads(canonical_bytes(scope))
            binding = OwnerBinding(ingress._reader._hub, 'integrations', 'effect-placeholder',
                                   'effect', canonical_bytes(enrolled_scope))
            credential = strict_loads(canonical_bytes(credential_ref))
            reference(credential)
            if (enrolled_scope['projectId'] is None
                    or credential['ownerHubId'] != binding.hub_id):
                raise ContractError('integration_router_configuration')
        except Exception:
            raise ContractError('integration_router_configuration') from None
        self._connection, self.ingress = connection, ingress
        self._authority = ingress._reader
        self._scope, self._scope_bytes = enrolled_scope, binding.scope
        self._provider = provider
        self._credential = canonical_bytes(credential)
        self._artifacts, self._credentials = artifacts, credentials
        self._factory = service_factory
        self._hub = binding.hub_id
        self._subject = '.'.join(('amx', 'v1', 'h', self._hub, 'o',
            enrolled_scope['organizationId'], 'integrations', '*', 'command'))
        self._services = {}
        self._service_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._subscription = self._subscribe_task = self._startup_task = self._drain_task = None
        self._callbacks, self._active = set(), set()
        self._closed, self._ready = False, False

    @classmethod
    def from_enrolled_host(cls, connection, *, authority, scope, provider,
                           credential_ref, issuer_ref, signing_seed,
                           service_factory, artifacts=None, credentials=None,
                           session_authorizer=None):
        if not isinstance(authority, LedgerAuthorityReader):
            raise ContractError('integration_enrolled_authority_required')
        ingress = EnrolledIngress(authority, issuer_ref=issuer_ref,
                                  signing_seed=signing_seed,
                                  session_authorizer=session_authorizer)
        return cls(connection, ingress, scope=scope, provider=provider,
                   credential_ref=credential_ref, service_factory=service_factory,
                   artifacts=artifacts, credentials=credentials)

    def __repr__(self):
        return '<IntegrationRouterService private>'

    @property
    def subject(self):
        return self._subject

    def check_health(self):
        if self._closed or not self._ready:
            raise ContractError('integration_service_unavailable')
        if self._startup_task is not None and self._startup_task.done():
            self._startup_task.result()
        for service in self._services.values():
            service.check_health()

    async def _verify_enrollment(self):
        snapshot = await self._authority.current()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._hub)
        now = _utc_now()
        issuer_ref = self.ingress._issuer_ref
        issuer = index['issuers'].get(_key(strict_loads(issuer_ref)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or identity is None
                or identity['kind'] != 'service' or not _active(identity, now)):
            raise ContractError('integration_issuer_unavailable')
        challenge = {'purpose': 'agentmux-integration-router-key-check-v1',
                     'hubId': self._hub, 'scope': self._scope}
        verify_possession(challenge, sign_claims(challenge, self.ingress._seed), issuer['publicKey'])

    async def start(self):
        async with self._lifecycle_lock:
            if self._closed or self._startup_task is not None:
                raise ContractError('integration_service_lifecycle')
            self._startup_task = asyncio.create_task(self._start_io())
        await asyncio.shield(self._startup_task)

    async def _start_io(self):
        try:
            await self._verify_enrollment()
            if self._closed:
                raise ContractError('integration_service_closed')
            self._ready = True
            self._subscribe_task = asyncio.create_task(self._connection.subscribe(
                self._subject, cb=self._receive, pending_msgs_limit=32,
                pending_bytes_limit=32 * 65536))
            self._subscription = await asyncio.shield(self._subscribe_task)
            await asyncio.wait_for(self._connection.flush(), 3)
        except BaseException:
            self._closed = True
            raise

    async def _route(self, request_bytes, subject):
        if type(request_bytes) is not bytes or len(request_bytes) > 65536:
            raise ContractError('owner_body_limit')
        request = strict_loads(request_bytes)
        validate('identity-ingress-request', request)
        contract = request['claims']['contractId']
        if contract not in COMMANDS:
            raise ContractError('integration_command_unsupported')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('integration_not_authorized')
        envelope = strict_loads(admitted.envelope)
        operation = envelope['operation']
        if canonical_bytes(operation['scope']) != self._scope_bytes:
            # Other explicitly enrolled project routers share the organization
            # wildcard. A route miss stays silent so only the owning router can
            # answer the request.
            raise ContractError('integration_route_not_enrolled')
        if contract == 'integration-intent':
            body = intent(envelope['payload'])
            original = operation['operationId']
        elif contract == 'integration-effect-query':
            body = query(envelope['payload'])
            original = body['originalOperationId']
        else:
            body = strict_loads(canonical_bytes(envelope['payload']))
            validate(contract, body)
            original = body['originalOperationId']
        if (contract in ('integration-intent', 'integration-attempt-start')
                and not operation['approvalRefs']):
            raise ContractError('integration_approval_required')
        if (contract == 'integration-intent'
                and (canonical_bytes(body['credentialRef']) != self._credential
                     or body['action'].split('-', 1)[0] != self._provider)):
            raise ContractError('integration_route_not_enrolled')
        entity = effect_id(operation['scope'], original)
        expected = self._subject.replace('*', entity)
        if subject is not None and subject != expected:
            raise ContractError('integration_access_refused')
        return entity, original

    async def _service(self, entity, original_operation_id):
        async with self._service_lock:
            service = self._services.get(entity)
            if service is not None:
                return service
            binding = OwnerBinding(self._hub, 'integrations', entity, 'effect', self._scope_bytes)
            service = self._factory(binding, original_operation_id)
            if inspect.isawaitable(service):
                service = await service
            if service is None:
                # Lifecycle commands do not carry a provider. The enrolled
                # factory is the exact effect index for that provider/project.
                raise ContractError('integration_route_not_enrolled')
            resolver = (None if type(service) is not IntegrationService
                or service.owner._worker is None else service.owner._worker._resolver)
            invalid = (type(service) is not IntegrationService or service._connection is not self._connection
                    or service._binding != binding or service.ingress._reader is not self._authority
                    or service.ingress._issuer_ref != self.ingress._issuer_ref
                    or service.ingress._seed != self.ingress._seed
                    or service.owner._provider != self._provider
                    or service.owner._credential != self._credential
                    or service.owner._artifacts is not self._artifacts
                    or resolver is not self._credentials)
            if invalid:
                if type(service) is IntegrationService:
                    await service.close()
                raise ContractError('integration_router_factory_invalid')
            try:
                await service.start_embedded()
            except BaseException:
                await service.close()
                raise
            self._services[entity] = service
            return service

    async def handle(self, request_bytes, *, subject=None):
        self.check_health()
        if len(self._active) >= 32:
            raise ContractError('integration_service_busy')
        completed = asyncio.get_running_loop().create_future()
        self._active.add(completed)
        try:
            entity, original = await self._route(request_bytes, subject)
            service = await self._service(entity, original)
            return await service.handle(request_bytes)
        finally:
            self._active.discard(completed)
            completed.set_result(None)

    async def _receive(self, message):
        if (self._closed or not isinstance(getattr(message, 'subject', None), str)
                or not isinstance(message.reply, str) or not re.fullmatch(
                    r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?', message.reply)):
            return
        try:
            if len(message.data) > 65536:
                return
            request = strict_loads(message.data)
            if request.get('claims', {}).get('replySubject') != message.reply:
                return
        except Exception:
            return
        if len(self._callbacks) >= 32:
            return
        task = asyncio.create_task(self._respond(message))
        self._callbacks.add(task)
        task.add_done_callback(self._reply_finished)
        await asyncio.shield(task)

    def _reply_finished(self, task):
        self._callbacks.discard(task)
        if not task.cancelled():
            task.exception()

    async def _respond(self, message):
        try:
            response = await asyncio.wait_for(
                self.handle(message.data, subject=message.subject), 10)
        except asyncio.CancelledError:
            raise
        except ContractError as error:
            if error.code == 'integration_route_not_enrolled':
                return
            response = canonical_bytes({'schemaVersion': '1.0.0',
                                        'error': 'integration_outcome_unconfirmed'})
        except Exception:
            response = canonical_bytes({'schemaVersion': '1.0.0',
                                        'error': 'integration_outcome_unconfirmed'})
        await self._connection.publish(message.reply, response)

    async def _drain(self):
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
                    pass
            if self._subscription is not None:
                await self._subscription.drain()
                self._subscription = None
        finally:
            if self._callbacks:
                await asyncio.gather(*tuple(self._callbacks), return_exceptions=True)
            if self._active:
                await asyncio.gather(*tuple(self._active), return_exceptions=True)
            await asyncio.gather(*(service.close() for service in tuple(self._services.values())),
                                 return_exceptions=False)

    async def close(self):
        async with self._lifecycle_lock:
            self._closed = True
            if (self._drain_task is None or (self._drain_task.done()
                    and not self._drain_task.cancelled() and self._drain_task.exception() is not None)):
                self._drain_task = asyncio.create_task(self._drain())
            await asyncio.wait_for(asyncio.shield(self._drain_task), 10)

