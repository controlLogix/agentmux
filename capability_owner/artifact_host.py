"""Serve declared artifact reads using the existing selected task owner."""
import asyncio

from agentmux_contracts import ContractError
from .artifact_resource import TaskArtifactResource
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageFailure


class ArtifactReadHost:
    def __init__(self, selection, *, identity, task, connection, signing_seed):
        from identity.application_service_selection import ApplicationServiceSelection
        from state_owner.task_host import TaskHost
        if (not isinstance(selection, ApplicationServiceSelection) or not isinstance(task, TaskHost)
                or selection.policy.get('artifact') is None or task._artifact_custody is None):
            raise ContractError('capability_artifact_configuration')
        self._authority, _ = selection.check_storage_identity_source(identity)
        if task.owner._authority is not self._authority:
            raise ContractError('capability_artifact_configuration')
        self._selection, self._identity, self._task = selection, identity, task
        self._connection, self._seed = connection, signing_seed
        self._loop = asyncio.get_running_loop()
        self._closed = self._ready = False
        self._starting = self._closing = self._service = None
        self._resource = TaskArtifactResource(task, selection=selection,
            artifacts=task._artifact_custody._artifacts)

    def __repr__(self):
        return '<ArtifactReadHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('capability_artifact_stale')
        self._resource.check_current()
        authority, _ = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority:
            raise ContractError('capability_artifact_stale')

    async def _start(self):
        from identity.artifact_selection import check_artifact_authority
        from state_owner.ledger import validate_record
        self._open()
        await check_artifact_authority(self._selection, self._identity)
        self._open()
        pin = self._selection.policy['artifact']
        snapshot = await self._task.ledger.current()
        if snapshot.latest is None:
            raise ContractError('capability_artifact_stale')
        record = validate_record(snapshot.latest.record, self._resource.binding)
        if record['entityVersion'] < pin['resourceRef']['revision']:
            raise ContractError('capability_artifact_stale')
        value, receiver = self._selection.policy, pin['receiver']
        service = CapabilityReplyService(self._authority, resources=[self._resource],
            hub_id=value['kernelScope']['hubId'], profile_id=value['kernelScope']['profileId'],
            authority_id=value['authorityId'], service_id='artifact-owner',
            service_identity_ref=receiver['serviceIdentityRef'], service_instance_id=receiver['serviceInstanceId'],
            signing_key_ref=receiver['issuer']['issuerRef'], signing_seed=self._seed,
            request_signing_key_ref=receiver['requestSigningKeyRef'], connection=self._connection)
        self._service = service
        await service.start()
        await check_artifact_authority(self._selection, self._identity)
        self._open()
        self._ready = True
        self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:
            raise ContractError('capability_artifact_stale')
        self._starting = asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
        except asyncio.CancelledError:
            self._closed = True
            raise
        except Exception as error:
            self._closed = True
            raise SelectedStorageFailure('capability_artifact_unavailable', self, error) from None

    def check_health(self):
        self._open()
        if (not self._ready or self._service is None or self._service._closed
                or self._service._subscription is None or self._connection.is_connected is not True):
            raise ContractError('capability_artifact_stale')

    def fence(self):
        self._closed, self._ready = True, False
        if self._service is not None:
            self._service._closed = True

    async def _cleanup(self):
        if self._starting is not None:
            if not self._starting.done():
                self._starting.cancel()
            await asyncio.gather(self._starting, return_exceptions=True)
        if self._service is not None:
            try:
                await self._service.close(timeout=10)
            except ContractError as error:
                if str(error) != 'capability_cleanup_incomplete' or self._service._cleanup_task is None:
                    raise
                await asyncio.gather(self._service._cleanup_task)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('capability_cleanup_invalid')
        if asyncio.get_running_loop() is not self._loop:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self)
        self.fence()
        failed = self._closing is not None and self._closing.done() and (
            self._closing.cancelled() or self._closing.exception() is not None)
        if self._closing is None or failed:
            self._closing = asyncio.create_task(self._cleanup())
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            _, pending = await asyncio.wait({self._closing}, timeout=timeout)
            if pending:
                raise TimeoutError()
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self, error) from None
