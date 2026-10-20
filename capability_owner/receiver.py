"""Receiving adapters using enrolled identity and existing retained owners.

This module does not provision streams, issue grants, dispatch external effects,
register a subscription or treat callbacks as authorization. The host must supply
an AuthorityReader and enroll the existing owner bindings before accepting calls.
"""
import asyncio
import base64
import importlib.util
import re
from dataclasses import dataclass

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import AuthorityReader
from identity.capability_routes import CAPABILITY_DESTINATIONS as _DESTINATIONS
from state_owner.ledger import validate_record
from .resources import RetainedResource
from .federation_board import FederationBoardResource
from .private_storage import PrivateStorageResource
from .board_publisher import BoardStorageRoute
from .policy import PolicyResource
from .messages import MessageStorageResource
from .federated_storage import FederatedStorageResource
from .secret_resource import OrdinarySecretResource
# Core packages deliberately omit Process execution. A present module must load
# successfully: its missing dependencies and other import errors are not absence.
if importlib.util.find_spec(__package__ + '.process_resource') is None:
    _PROCESS_RESOURCE_TYPES = ()
else:
    from .process_resource import ProcessResource
    _PROCESS_RESOURCE_TYPES = (ProcessResource,)

_READS = {'capability-storage-read', 'capability-artifact-read', 'capability-outcome-query', 'capability-workspace-read'}


@dataclass(frozen=True, repr=False)
class CapabilityResponse:
    """Private reply payload; the host must authenticate transport before delivery."""
    contract_id: str
    request_digest: str
    operation_id: str
    payload: bytes

    def __repr__(self):
        return '<CapabilityResponse private>'


class CapabilityReceiver:
    def __init__(self, authority, *, hub_id, resources, board_routes=(), receiving_connection=None):
        if (not isinstance(authority, AuthorityReader) or not isinstance(hub_id, str)
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', hub_id)):
            raise ContractError('capability_owner_configuration')
        self._authority, self._hub = authority, hub_id
        self._resources = {}
        for resource in resources:
            if not isinstance(resource, (RetainedResource, FederationBoardResource, PrivateStorageResource, PolicyResource, MessageStorageResource, FederatedStorageResource, OrdinarySecretResource) + _PROCESS_RESOURCE_TYPES) or resource.binding.hub_id != hub_id:
                raise ContractError('capability_owner_configuration')
            key = resource.binding.entity_id
            if key in self._resources or len(self._resources) >= 256:
                raise ContractError('capability_owner_configuration')
            self._resources[key] = resource
        self._board_routes={}
        self._receiving_connection=receiving_connection
        for route in board_routes:
            if type(route) is not BoardStorageRoute:
                raise ContractError('capability_owner_configuration')
            resource=route.resource
            if (self._resources.get(resource.binding.entity_id) is not resource
                    or resource.binding.entity_id in self._board_routes):
                raise ContractError('capability_owner_configuration')
            route.check_registration(authority,resource,receiving_connection)
            self._board_routes[resource.binding.entity_id]=route
        self._active = set()
        self._workers = set()
        self._closed = False

    def __repr__(self):
        return '<CapabilityReceiver private>'

    async def close(self, *, timeout=5.0):
        """Cancel calls and join original reads; retain ownership on timeout."""
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('capability_cleanup_invalid')
        self._closed = True
        active = tuple(self._active)
        for task in active:
            task.cancel()
        pending = {*active, *self._workers}
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=timeout)
            if unfinished:
                raise ContractError('capability_cleanup_incomplete')

    def check_current(self, reference):
        """Host reply boundary: recheck borrowed owner state without awaiting."""
        if self._closed:
            raise ContractError('capability_owner_closed')
        resource = self._resources.get(reference['id'])
        if resource is None or reference['ownerHubId'] != self._hub:
            raise ContractError('capability_access_refused')
        if isinstance(resource, (FederationBoardResource, MessageStorageResource, FederatedStorageResource, OrdinarySecretResource) + _PROCESS_RESOURCE_TYPES):
            resource._current()
        if isinstance(resource, RetainedResource):
            resource.check_current()
        route=self._board_routes.get(reference['id'])
        if route is not None:
            route.check(self._authority,resource,self._receiving_connection)

    def check_service_request(self, snapshot, claims):
        resource = self._resources.get(claims['resourceRef']['id'])
        if isinstance(resource, (PrivateStorageResource, PolicyResource, MessageStorageResource, FederatedStorageResource, OrdinarySecretResource) + _PROCESS_RESOURCE_TYPES):
            resource.check_request(snapshot, claims)

    async def check_disclosure(self, raw):
        """Join the work actor check before the host signs the final response."""
        reference = strict_loads(raw)['payload']['resourceRef']
        self.check_current(reference)
        resource = self._resources[reference['id']]
        if isinstance(resource, FederatedStorageResource) and resource.domain == 'work':
            from .work import WorkStorageResource
            if type(resource) is not WorkStorageResource:
                raise ContractError('capability_access_refused')
            if len(self._workers) >= 32:
                raise ContractError('capability_owner_capacity')
            worker = asyncio.create_task(resource.check_disclosure(raw))
            self._workers.add(worker)
            def finished(original):
                self._workers.discard(original)
                if not original.cancelled():
                    original.exception()
            worker.add_done_callback(finished)
            await asyncio.shield(worker)
        self.check_current(reference)

    async def _workspace_read(self, workspace, relative, repository_id):
        # Shield the original worker from request cancellation. A timeout can
        # discard its result, but close must still join this exact worker before
        # the host releases the borrowed checkout. Never start a replacement.
        if self._closed or len(self._workers) >= 32:
            raise ContractError('capability_service_unavailable')
        worker = asyncio.create_task(asyncio.to_thread(workspace.read, relative,
            repository_id=repository_id))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _private_write(self, resource, raw, service_request_bytes):
        # Keep the exact dispatched write through request cancellation. A lost
        # reply is uncertain; close joins this same worker before releasing I/O.
        if self._closed or len(self._workers) >= 32:
            raise ContractError('capability_service_unavailable')
        worker = asyncio.create_task(resource.write(self._authority, raw, service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _secret_call(self, resource, raw, service_request_bytes):
        if self._closed or len(self._workers) >= 32:
            raise ContractError('capability_service_unavailable')
        worker = asyncio.create_task(resource.call(raw, service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _artifact_read(self, resource, reference):
        # The caller may leave before Object Store responds. Retain that exact
        # read until close joins it, before releasing the borrowed task owner.
        if self._closed or len(self._workers) >= 32:
            raise ContractError('capability_service_unavailable')
        worker = asyncio.create_task(resource.artifacts.retrieve(reference))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _board_call(self, owner, contract, raw, service_request_bytes):
        # Retain the exact write or recovery worker through reply cancellation.
        # The host closes the publisher only after these borrowed calls join.
        if self._closed or len(self._workers)>=32:
            raise ContractError('capability_service_unavailable')
        operation=(owner.apply if contract=='capability-storage-write' else owner.reconcile)
        worker=asyncio.create_task(operation(raw,service_request_bytes=service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _policy_evaluate(self, resource, raw, service_request_bytes):
        if self._closed or len(self._workers) >= 32:
            raise ContractError('capability_service_unavailable')
        worker = asyncio.create_task(resource.evaluate(self._authority, raw, service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def handle(self, envelope_bytes, *, service_request_bytes=None):
        if self._closed:
            raise ContractError('capability_owner_closed')
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError()
        if len(self._active) + len(self._workers) >= 32:
            raise ContractError('capability_owner_capacity')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with asyncio.timeout(5):
                return await self._handle(envelope_bytes, service_request_bytes)
        except asyncio.CancelledError:
            raise
        except ContractError as exc:
            # Only public, fixed refusal classes cross this boundary. SDK and
            # broker diagnostics can contain private field names or paths.
            if str(exc) in {'capability_owner_closed', 'capability_owner_capacity',
                            'capability_access_refused', 'capability_resource_stale',
                            'capability_service_unavailable', 'capability_outcome_conflict'}:
                raise
            raise ContractError('capability_owner_unavailable') from None
        except Exception:
            raise ContractError('capability_owner_unavailable') from None
        finally:
            self._active.discard(task)

    async def _authorize(self, raw, contract, resource, operation, service_request_bytes):
        route=self._board_routes.get(resource.binding.entity_id)
        if route is not None:
            owner=route.check(self._authority,resource,self._receiving_connection)
            if contract=='capability-storage-write':
                _,decision=await owner._journal._authorize(raw,{'capability-storage-write'},service_request_bytes)
            elif contract=='capability-outcome-query':
                envelope=await owner._authorize_recovery(raw,service_request_bytes,query=True)
                if envelope['operation']!=operation:
                    raise ContractError('capability_access_refused')
                return
            else:
                decision=await self._authority.evaluate(raw,audience={
                    'hubId':self._hub,'serviceId':_DESTINATIONS[contract]})
        elif isinstance(resource, PolicyResource):
            _, _, decision = await resource.authorize(self._authority, raw, service_request_bytes)
        elif isinstance(resource, (PrivateStorageResource, MessageStorageResource, FederatedStorageResource, OrdinarySecretResource) + _PROCESS_RESOURCE_TYPES):
            decision = await resource.authorize(self._authority, raw, service_request_bytes)
        else:
            decision = await self._authority.evaluate(raw, audience={
                'hubId': self._hub, 'serviceId': _DESTINATIONS[contract]})
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                or canonical_bytes(operation['scope']) != resource.binding.scope):
            raise ContractError('capability_access_refused')
        if isinstance(resource, RetainedResource):
            resource.check_current()
            if contract == 'capability-artifact-read':
                snapshot = await resource.ledger.current()
                if snapshot.latest is None:
                    raise ContractError('capability_resource_stale')
                record = validate_record(snapshot.latest.record, resource.binding)
                if record['entityVersion'] != strict_loads(raw)['payload']['resourceRef']['revision']:
                    raise ContractError('capability_resource_stale')
                # Keep initial denial ahead of owner I/O, and refresh authority
                # after that awaited read before allowing artifact disclosure.
                decision = await self._authority.evaluate(raw, audience={
                    'hubId':self._hub, 'serviceId':_DESTINATIONS[contract]})
                if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                        or canonical_bytes(operation['scope']) != resource.binding.scope):
                    raise ContractError('capability_access_refused')
                resource.check_current()
        if contract == 'capability-workspace-read' and isinstance(resource, RetainedResource) and resource.workspace is not None:
            await resource.workspace.check_current()

    async def _handle(self, raw, service_request_bytes):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('capability_access_refused')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        contract = envelope['contractId']
        if contract not in _DESTINATIONS:
            raise ContractError('capability_access_refused')
        validate(contract, envelope['payload'])
        ref = envelope['payload']['resourceRef']
        resource = self._resources.get(ref['id'])
        if resource is None or ref['ownerHubId'] != self._hub:
            raise ContractError('capability_access_refused')
        operation = envelope['operation']
        await self._authorize(raw, contract, resource, operation, service_request_bytes)
        if self._closed:
            raise ContractError('capability_owner_closed')
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError()
        route=self._board_routes.get(ref['id'])
        if route is not None and contract in ('capability-storage-write','capability-outcome-query'):
            owner=route.check(self._authority,resource,self._receiving_connection)
            result=await self._board_call(owner,contract,raw,service_request_bytes)
            reply_contract=('capability-storage-write-reply' if contract=='capability-storage-write'
                            else 'capability-outcome-query-reply')
        elif isinstance(resource, _PROCESS_RESOURCE_TYPES) and contract in ('capability-process-start','capability-process-cancel','capability-outcome-query'):
            result = await self._secret_call(resource, raw, service_request_bytes)
            reply_contract = contract+'-reply'
        elif isinstance(resource, OrdinarySecretResource) and contract in ('capability-secret-use', 'capability-outcome-query'):
            result = await self._secret_call(resource, raw, service_request_bytes)
            reply_contract = ('capability-secret-use-reply' if contract == 'capability-secret-use'
                else 'capability-outcome-query-reply')
        elif contract == 'capability-outcome-query' and isinstance(resource, (MessageStorageResource, FederatedStorageResource)):
            result = await resource.reconcile(raw)
            reply_contract = 'capability-outcome-query-reply'
        elif contract == 'capability-storage-write' and isinstance(resource, (PrivateStorageResource, MessageStorageResource, FederatedStorageResource)):
            result = await self._private_write(resource, raw, service_request_bytes)
            reply_contract = 'capability-storage-write-reply'
        elif contract == 'capability-policy-evaluate' and isinstance(resource, PolicyResource):
            result = await self._policy_evaluate(resource, raw, service_request_bytes)
            reply_contract = 'capability-policy-evaluate-reply'
        elif contract in _READS:
            result, reply_contract = await self._read(contract, envelope['payload'], resource)
        else:
            raise ContractError('capability_service_unavailable')
        # A revoked or expired caller must not receive data after a slow owner read.
        await self._authorize(raw, contract, resource, operation, service_request_bytes)
        self.check_current(envelope['payload']['resourceRef'])
        if self._closed:
            raise ContractError('capability_owner_closed')
        if asyncio.current_task().cancelling():
            raise asyncio.CancelledError()
        validate(reply_contract, result)
        payload = canonical_bytes(result)
        if len(payload) > 65536:
            raise ContractError('capability_service_unavailable')
        return CapabilityResponse(reply_contract, payload_digest(envelope), operation['operationId'], payload)

    async def _read(self, contract, payload, resource):
        # Internal I/O only. handle is the receiving boundary and authorizes both
        # before this read and before disclosure. Never expose _read to plugins.
        ref, inputs = payload['resourceRef'], payload['input']
        if isinstance(resource, PrivateStorageResource):
            if contract == 'capability-storage-read':
                data = await resource.read(ref['revision'])
                return {'resourceRef': ref, 'data': base64.b64encode(data).decode('ascii')}, 'capability-content-reply'
            if contract != 'capability-outcome-query':
                raise ContractError('capability_service_unavailable')
        if isinstance(resource, (FederationBoardResource, MessageStorageResource, FederatedStorageResource, OrdinarySecretResource)):
            if contract != 'capability-storage-read':
                raise ContractError('capability_service_unavailable')
            data = await resource.read(ref['revision'])
            return {'resourceRef': ref, 'data': base64.b64encode(data).decode('ascii')}, 'capability-content-reply'
        if contract == 'capability-outcome-query':
            try:
                stored = await resource.ledger.outcome(inputs['operationId'], inputs['payloadDigest'])
            except ContractError as exc:
                if str(exc) == 'owner_operation_conflict':
                    raise ContractError('capability_outcome_conflict') from None
                raise
            result = {'operationId': inputs['operationId'], 'payloadDigest': inputs['payloadDigest'],
                      'recordRef': None, 'outcome': 'absent'}
            if stored is not None:
                record = validate_record(stored.record, resource.binding)
                if isinstance(resource, PrivateStorageResource):
                    resource.document(stored.record)
                audit = record.get('authorizationDecision')
                # The query's claimed contract is not historical proof. Only the
                # original retained owner's audit can bind that contract to the
                # exact operation and actor. Never infer it from effect intents.
                if (not isinstance(audit, dict)
                        or audit.get('contractId') != inputs['contractId']
                        or audit.get('operationId') != inputs['operationId']
                        or audit.get('actorRef') != record['operation']['effectiveActorRef']):
                    raise ContractError('capability_access_refused')
                result.update(recordRef={'id': record['recordId'], 'ownerHubId': record['ownerHubId'],
                                         'revision': record['entityVersion']}, outcome=record['outcome'])
            if inputs['contractId'] == 'capability-storage-write':
                result['contractId'] = 'capability-storage-write'
                result['resourceRef'] = (None if stored is None else {
                    'id':resource.binding.entity_id,'ownerHubId':resource.binding.hub_id,
                    'revision':record['entityVersion']})
            reply_contract = 'capability-outcome-query-reply'
        else:
            snapshot = await resource.ledger.current()
            if snapshot.latest is None:
                raise ContractError('capability_resource_stale')
            record = validate_record(snapshot.latest.record, resource.binding)
            if record['entityVersion'] != ref['revision']:
                raise ContractError('capability_resource_stale')
            if contract == 'capability-storage-read':
                # Preserve the complete owner record, including unknown state
                # fields, IDs, provenance and effect intent. No projection write.
                data = snapshot.latest.record
            elif contract == 'capability-workspace-read':
                if resource.workspace is None or record['repository'] is None:
                    raise ContractError('capability_service_unavailable')
                data = await self._workspace_read(resource.workspace, inputs['relativePath'],
                    record['repository']['repositoryId'])
            else:
                matches = [a for a in record['artifacts'] if a['digest'] == inputs['digest']]
                if (len(matches) != 1 or resource.artifacts is None
                        or matches[0]['bytes'] > 45000):
                    raise ContractError('capability_service_unavailable')
                data = await self._artifact_read(resource, matches[0])
            if len(data) > 45000:
                raise ContractError('capability_service_unavailable')
            result = {'resourceRef': ref, 'data': base64.b64encode(data).decode('ascii')}
            reply_contract = 'capability-content-reply'
        return result, reply_contract
