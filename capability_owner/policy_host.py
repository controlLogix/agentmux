"""Selected policy service; the application host owns borrowed I/O resources."""
import asyncio
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import _active, _indexes, _key
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, owner_subject
from .policy import PolicyResource
from .reply_service import CapabilityReplyService
from .selected_storage import _StorageBackupLifecycle, _StorageLedgerCustody


class PolicyHost:
    def __init__(self, selection, *, identity, connection, history, checkpoint_host, backup_host, signing_seed):
        if not isinstance(selection, ApplicationServiceSelection):
            raise ContractError('policy_host_configuration')
        selected = selection.service('policy')
        binding, source = selection.binding('policy'), selection.stream_identity('policy')
        if (not isinstance(history, OwnerHistory) or history.binding != binding or history.source_identity != source
                or str(history._path) != selected['ledger']['history']['path']
                or history.max_records != selected['ledger']['history']['maxRecords']
                or history.max_bytes != selected['ledger']['history']['maxBytes']
                or not isinstance(checkpoint_host, CheckpointHost) or checkpoint_host.binding != binding
                or checkpoint_host.stream != selected['ledger']['stream'] or checkpoint_host.stream_identity != source
                or str(checkpoint_host.checkpoint_prefix) != selected['ledger']['checkpoint']['path']
                or checkpoint_host.commit_ref != selected['ledger']['checkpoint']['commitRef']
                or not isinstance(backup_host, BackupHost) or backup_host.binding != binding
                or backup_host.stream_identity != source
                or tuple(map(str, backup_host._roots)) != tuple(selected['backup'][key]
                    for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'))
                or backup_host._destination_id != selected['backup']['destinationId']):
            raise ContractError('policy_host_configuration')
        selection._check_seed('policy', signing_seed)
        self._selection, self._identity = selection, identity
        self._connection = connection
        self._authority, self._ingress = selection.check_storage_identity_source(identity)
        self._loop = asyncio.get_running_loop()
        domain = selected['connection']['jetstreamDomain']
        js = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        self.ledger = OwnerLedger(js, stream=selected['ledger']['stream'], subject=owner_subject(binding),
            binding=binding, retention=selection.retention('policy'), stream_identity=source,
            history=history, require_completion_budget=True)
        resource = PolicyResource(binding, self.ledger, canonical_bytes(selected['policyRef']),
            canonical_bytes(selected['pluginIdentityRef']), selected['instanceId'])
        value = selection.policy
        self.service = CapabilityReplyService(self._authority, resources=[resource], hub_id=binding.hub_id,
            profile_id=value['kernelScope']['profileId'], authority_id=value['authorityId'], service_id='policy-owner',
            service_identity_ref=selected['serviceIdentityRef'], service_instance_id=selected['serviceInstanceId'],
            signing_key_ref=selected['issuer']['issuerRef'], signing_seed=signing_seed,
            request_signing_key_ref=selected['requestSigningKeyRef'], connection=connection)

        async def unavailable_artifact(_reference):
            raise ContractError('policy_backup_artifact_unavailable')

        backup = _StorageBackupLifecycle(history, binding, source, backup_host,
            key_id=selected['backup']['keyId'], retrieve_artifact=unavailable_artifact, ledger=self.ledger)
        # Reuse the existing joined ledger custody, checkpoint and backup rules.
        # The application host retains the actual history and transport owners.
        self._custody = _StorageLedgerCustody(self.ledger, history, checkpoint_host, backup)
        self._closed = self._ready = False
        self._starting = self._closing = None

    def __repr__(self):
        return '<PolicyHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('policy_host_unavailable')
        reader, ingress = self._selection.check_storage_identity_source(self._identity)
        if reader is not self._authority or ingress is not self._ingress:
            raise ContractError('policy_host_unavailable')

    async def _check_authority(self):
        self._open()
        snapshot = await self._authority.current()
        self._open()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], record['ownerHubId'])
        selected = self._selection.service('policy')
        now = datetime.now(timezone.utc)
        def current(collection, reference):
            item = index[collection].get(_key(reference))
            if item is None or not _active(item, now):
                raise ContractError('policy_host_unavailable')
            return item
        principal = current('identities', selected['serviceIdentityRef'])
        signer = current('issuers', selected['issuer']['issuerRef'])
        requester = current('issuers', selected['requestSigningKeyRef'])
        requester_identity = current('identities', requester['identityRef'])
        plugin = current('identities', selected['pluginIdentityRef'])
        if (principal['kind'] != 'service' or requester_identity['kind'] != 'service' or plugin['kind'] != 'plugin'
                or signer['identityRef'] != principal['ref'] or signer['publicKey'] != selected['issuer']['publicKey']
                or signer['instanceId'] != selected['serviceInstanceId']):
            raise ContractError('policy_host_unavailable')
        # Services start before native activation. Every actual query separately
        # requires the exact active generation, current policy and ancestry.

    async def _start(self):
        await self._check_authority()
        await self._custody.start()
        self._open()
        await self.service.start()
        await self._check_authority()
        self._ready = True
        self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:
            raise ContractError('policy_host_unavailable')
        self._starting = asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            await asyncio.shield(self._starting)
        except BaseException:
            self.fence()
            raise

    def check_health(self):
        try:
            self._open()
            if (not self._ready or self.service._closed or self.service._subscription is None
                    or self._connection.is_connected is not True):
                raise ContractError('policy_host_unavailable')
            self._custody.check()
        except Exception:
            self.fence()
            raise ContractError('policy_host_unavailable') from None

    def fence(self):
        self._closed, self._ready = True, False
        self.service._closed = True

    async def _cleanup(self):
        if self._starting is not None:
            if not self._starting.done():
                self._starting.cancel()
            await asyncio.gather(self._starting, return_exceptions=True)
        await self.service.close()
        await self._custody.close()

    async def close(self, *, timeout=5):
        if (asyncio.get_running_loop() is not self._loop
                or timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10)):
            raise ContractError('policy_host_cleanup_incomplete')
        self.fence()
        if self._closing is None or self._closing.done() and (
                self._closing.cancelled() or self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._cleanup())
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('policy_host_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('policy_host_cleanup_incomplete') from None
