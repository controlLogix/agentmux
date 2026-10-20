"""Receive enrolled definition commands after an explicit persistent writer handoff.

The host supplies its scoped connection and actual authority, ledger and artifacts.
No HTTP actor label, filesystem fence or response receipt grants permission.
"""
import asyncio
from pathlib import Path
import re
import time
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.ingress import EnrolledIngress, verify_possession
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, _utc_now
from state_owner.ledger import OwnerLedger, owner_subject
from definition_service import DefinitionService
from state_owner.checkpoints import CheckpointCadence, CheckpointReceipt, export_checkpoint_async
from definition_commands import (DefinitionCommandOwner, DefinitionReceipt,
                                 LocalDefinitionOutcomeUnconfirmed)
from definition_completion import EFFECT_COMMANDS
from identity.local_browser_session import verified_local_browser_context


class DefinitionCommandService:
    def __init__(self, connection, owner, ingress, *, checkpoint_path, checkpoint_committed):
        if (not isinstance(owner, DefinitionCommandOwner) or not isinstance(ingress, EnrolledIngress)
                or ingress._reader is not owner._authority):
            raise ContractError('definition_service_configuration')
        self.owner, self.ingress = owner, ingress
        self.ledger = owner._ledger
        self._binding = owner._binding
        self._history = self.ledger._history
        self._stream_identity = self.ledger._identity
        self._checkpoint_path, self._checkpoint_committed = checkpoint_path, checkpoint_committed
        self._hub, self._entity, self._profile = (owner._authority._hub, owner._authority._entity,
                                                 owner._authority._profile)
        if self._hub != self._binding.hub_id:
            raise ContractError('definition_service_configuration')
        organization = strict_loads(self._binding.scope)['organizationId']
        self._subject = '.'.join(('amx', 'v1', 'h', self._hub, 'o', organization,
                                  'definitions', self._binding.entity_id, 'command'))
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
    def from_enrolled_host(cls, connection, *, scope, authority, binding, stream,
                           stream_identity, retention, history, artifacts, issuer_ref,
                           signing_seed, checkpoint_path, checkpoint_committed, jetstream_domain=None):
        """Compose the host's existing enrolled resources; provision nothing.

        The host owns connection credentials, stream identity, private history,
        artifact store, issuer key and checkpoint acknowledgement. Call start
        before advertising this route and close before releasing those resources.
        A named JetStream domain comes only from the enrolled host selection;
        None preserves the explicitly selected default API prefix.
        """
        if not isinstance(authority, LedgerAuthorityReader):
            raise ContractError('definition_enrolled_authority_required')
        if (jetstream_domain is not None and (type(jetstream_domain) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', jetstream_domain))):
            raise ContractError('definition_jetstream_domain_invalid')
        jetstream = (connection.jetstream() if jetstream_domain is None else
                     connection.jetstream(domain=jetstream_domain))
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding),
            binding=binding, retention=retention, stream_identity=stream_identity, history=history,
            require_completion_budget=True)
        owner = DefinitionCommandOwner(DefinitionService(scope), authority, ledger, binding, artifacts)
        ingress = EnrolledIngress(authority, issuer_ref=issuer_ref, signing_seed=signing_seed)
        return cls(connection, owner, ingress, checkpoint_path=checkpoint_path,
                   checkpoint_committed=checkpoint_committed)

    def __repr__(self):
        return '<DefinitionCommandService private>'

    @property
    def subject(self):
        return self._subject

    async def handle(self, request_bytes):
        if self._closed or not self._ready:
            raise ContractError('definition_service_unavailable')
        if len(self._active) >= 32:
            raise ContractError('definition_service_busy')
        for task in (self._checkpoint_work, self._checkpoint_task):
            if task is not None and task.done():
                task.result()
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

    async def handle_local_browser(self, context, target, body, *, operation_id=None):
        """Run one enrolled local edit through this service's durable owner."""
        if self._closed or not self._ready:
            raise ContractError('definition_service_unavailable')
        if not verified_local_browser_context(context):
            raise ContractError('local_browser_context_invalid')
        if len(self._active) >= 32:
            raise ContractError('definition_service_busy')
        for task in (self._checkpoint_work, self._checkpoint_task):
            if task is not None and task.done():
                task.result()
        completed = asyncio.get_running_loop().create_future()
        self._active.add(completed)
        try:
            await self._recover()
            receipt = await self.owner.execute_local_browser(
                context, target, body, operation_id=operation_id)
            if not isinstance(receipt, DefinitionReceipt) or receipt.file_status != 'applied':
                recovery_id = operation_id if operation_id is not None else getattr(receipt, 'operation_id', None)
                if recovery_id is not None:
                    raise LocalDefinitionOutcomeUnconfirmed(
                        'definition_outcome_unconfirmed', recovery_id)
                raise ContractError('definition_outcome_unconfirmed')
            try:
                await self.owner.complete_local_browser(context, receipt)
                self._checkpoint_if_due()
                if target == '/api/board/agentdef':
                    return await asyncio.to_thread(self.owner._service.agents, None, {'name': [body['name']]})
                return {'ok': True, 'scope': body['scope'], 'name': body['name']}
            except LocalDefinitionOutcomeUnconfirmed:
                raise
            except Exception as error:
                # The intent and file effect already exist. Preserve their exact
                # recovery identity; no later denial or readback failure may be
                # mistaken for a fresh sign-in failure and submitted again.
                code = getattr(error, 'code', 'definition_outcome_unconfirmed')
                raise LocalDefinitionOutcomeUnconfirmed(code, receipt.operation_id) from None
        finally:
            self._active.discard(completed)
            completed.set_result(None)

    async def _handle(self, request_bytes):
        if type(request_bytes) is not bytes or len(request_bytes) > 65536:
            raise ContractError('owner_body_limit')
        request = strict_loads(request_bytes)
        validate('identity-ingress-request', request)
        if request['claims']['contractId'] not in ('definition-save', 'definition-drop', *EFFECT_COMMANDS):
            raise ContractError('definition_command_unsupported')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('definition_not_authorized')
        receipt = await self.owner.execute(admitted.envelope)
        if isinstance(receipt, DefinitionReceipt):
            outcome = {'operationId': operation_id, 'originalOperationId': operation_id,
                'effectId': receipt.effect_id, 'definitionVersion': receipt.definition_version,
                'currentDefinitionVersion': None, 'catalogSequence': receipt.sequence,
                'receiptSequence': None, 'attemptOperationId': receipt.attempt_operation_id,
                'status': 'intent-committed', 'replayed': receipt.replayed, 'observedAt': None}
        else:
            outcome = {'operationId': operation_id, 'originalOperationId': receipt.original_operation_id,
                'effectId': receipt.effect_id, 'definitionVersion': receipt.definition_version,
                'currentDefinitionVersion': receipt.current_definition_version,
                'catalogSequence': receipt.catalog_sequence, 'receiptSequence': receipt.receipt_sequence,
                'attemptOperationId': receipt.attempt_operation_id, 'status': receipt.status,
                'replayed': receipt.replayed, 'observedAt': receipt.observed_at}
        claims = {'purpose': 'agentmux-definition-command-receipt-v1', 'hubId': self._hub,
            'profileId': self._profile, 'authorityId': self._entity, 'issuerRef': strict_loads(self._issuer),
            'requestDigest': payload_digest(request), 'receipt': outcome}
        response = {'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, self._seed)}
        validate('definition-command-receipt', response)
        return canonical_bytes(response)

    async def _verify_enrollment(self):
        snapshot = await self.owner._authority.current()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._hub)
        now = _utc_now()
        issuer = index['issuers'].get(_key(strict_loads(self._issuer)))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or identity is None
                or identity['kind'] != 'service' or not _active(identity, now)):
            raise ContractError('definition_issuer_unavailable')
        challenge = {'purpose': 'agentmux-definition-host-key-check-v1',
                     'hubId': self._hub, 'catalogId': self._binding.entity_id}
        verify_possession(challenge, sign_claims(challenge, self._seed), issuer['publicKey'])

    async def _recover(self):
        async with self._recovery_lock:
            while not self._closed:
                progress = await self.ledger.prepare_history()
                if progress.ready:
                    return
                await asyncio.sleep(0)
            raise ContractError('definition_service_closed')

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
                raise ContractError('definition_service_lifecycle')
            if (self._history is None or not self.ledger.completion_budget_required
                    or self._checkpoint_path is None or not callable(self._checkpoint_committed)):
                raise ContractError('definition_history_configuration_required')
            self._startup_task = asyncio.create_task(self._start_io())
        # Recovery can need many pages. Never hold the lifecycle lock while it
        # runs; close must be able to stop it and join this original task.
        await asyncio.shield(self._startup_task)

    async def _start_io(self):
        try:
            await self._recover()
            if self._closed:
                raise ContractError('definition_service_closed')
            await self._verify_enrollment()
            await self.owner.activate_writer()
            if self._closed:
                raise ContractError('definition_service_closed')
            self._ready = True
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
        completed = asyncio.get_running_loop().create_future()
        self._callbacks.add(completed)
        try:
            try:
                response = await asyncio.wait_for(self.handle(message.data), 10)
            except asyncio.CancelledError:
                raise
            except Exception:
                # A timeout may follow a commit. Preserve the original operation
                # identity so the client can reconcile its uncertain outcome.
                response = canonical_bytes({'schemaVersion': '1.0.0',
                                            'error': 'definition_outcome_unconfirmed'})
            await self._connection.publish(message.reply, response)
        finally:
            self._callbacks.discard(completed)
            completed.set_result(None)

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
    if (type(response_bytes) is not bytes or len(response_bytes) > 65536
            or type(request_bytes) is not bytes or len(request_bytes) > 65536):
        raise ContractError('definition_receipt_invalid')
    response, request = strict_loads(response_bytes), strict_loads(request_bytes)
    validate('identity-ingress-request', request)
    if (type(response) is not dict or set(response) != {'schemaVersion', 'claims', 'signature'}
            or response['schemaVersion'] != '1.0.0'):
        raise ContractError('definition_outcome_unconfirmed')
    validate('definition-command-receipt', response)
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims.get('purpose') != 'agentmux-definition-command-receipt-v1'
            or claims.get('issuerRef') != issuer_ref
            or claims.get('requestDigest') != payload_digest(request)
            or any(claims.get(k) != request['claims'][k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('receipt', {}).get('operationId') != request['claims']['operationId']):
        raise ContractError('definition_receipt_binding')
    return strict_loads(canonical_bytes(claims['receipt']))
