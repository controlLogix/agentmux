"""Selected ordinary-secret receivers and joined private owner lifetimes."""
import asyncio
import base64
import ssl

import nkeys
from agentmux_contracts import ContractError, strict_loads
from hub.fed.session import FederationSession
from hub.nats_transport import new_client
from identity.secret_selection import (check_secret_authority, load_receiver, load_signer,
    selection_objects)
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from native_security.secret_custody import ScopedSecretCustody
from .reply_service import CapabilityReplyService
from .secret_journal_admission import SecretJournalAdmission
from .secret_resource import OrdinarySecretResource, SecretResolveSigner
from .selected_storage import SelectedStorageFailure


class SecretUseHost:
    def __init__(self, selection, *, identity):
        from identity.application_service_selection import ApplicationServiceSelection
        if type(selection) is not ApplicationServiceSelection or selection.policy.get('ordinarySecret') is None:
            raise ContractError('capability_secret_configuration')
        self._selection, self._identity = selection, identity
        self._authority, self._ingress = selection.check_storage_identity_source(identity)
        self._loop = asyncio.get_running_loop()
        self._closed = self._ready = False
        self._starting = self._closing = self._resource = self._admission = self._verification = None
        self._clients, self._sessions, self._connects, self._receivers, self._files = [], [], [], [], set()

    def __repr__(self):
        return '<SecretUseHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:
            raise ContractError('capability_secret_stale')
        if self._selection.check_storage_identity_source(self._identity)[0] is not self._authority:
            raise ContractError('capability_secret_stale')

    async def _file(self, function, *args):
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        self._files.add(task)
        try:
            await asyncio.wait({task})
            return task.result()
        finally:
            if task.done():
                self._files.discard(task)

    async def _lost(self, *_args):
        self.fence()

    async def _connect(self, name, credential):
        pin = self._selection.policy['ordinarySecret']['receivers'][name]
        connection = pin['connection']
        client = new_client(require_tls=True, leaf_certificate_sha256=connection['leafCertificateSHA256'])
        self._clients.append(client)
        session = FederationSession()
        self._sessions.append(session)
        client._agentmux_session = session
        def signature(nonce):
            current, _ = load_receiver(self._selection, name)
            key = nkeys.from_seed(current.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:
                key.wipe()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=connection['rootsPEM'])
        original = asyncio.create_task(client.connect(servers=[connection['endpoint']], tls=context,
            tls_hostname=connection['serverName'], tls_handshake_first=True,
            user_jwt_cb=lambda: load_receiver(self._selection, name)[0].jwt.encode('ascii'),
            signature_cb=signature, inbox_prefix=pin['credentials']['replyPrefix'],
            name='agentmux-'+name+'-secret-service', allow_reconnect=False,
            max_reconnect_attempts=0, connect_timeout=3, dont_randomize=True, no_echo=True,
            disconnected_cb=self._lost, reconnected_cb=self._lost, closed_cb=self._lost,
            error_cb=self._lost))
        self._connects.append(original)
        await asyncio.wait({original})
        original.result()
        self._open()
        if client.is_connected is not True:
            raise ContractError('capability_secret_unavailable')
        return client

    async def _start(self):
        self._open()
        await check_secret_authority(self._selection, self._identity)
        pin = self._selection.policy['ordinarySecret']
        enrollment, policy = selection_objects(pin)
        custody_seed = await self._file(load_signer, pin['signer'])
        account_seed = await self._file(load_signer, pin['account'])
        self._verification = OrdinarySecretCustody(pin['custodyRoot'], self._authority)
        account_custody = ScopedSecretCustody(pin['accountCustodyRoot'], self._authority)
        self._admission = SecretJournalAdmission(policy=policy, enrollment=enrollment,
            authority=self._authority, custody=self._verification, account_custody=account_custody,
            inventory_root=pin['journal']['inventoryRoot'], observation_root=pin['journal']['observationRoot'])
        signer = SecretResolveSigner(self._ingress, enrollment=enrollment,
            custody_transport=pin['signer']['transportRef'], custody_seed=custody_seed,
            resolve_grant=pin['signer']['resolveGrant'], phase_grants=pin['signer']['phaseGrants'],
            account_transport=pin['account']['transportRef'], account_seed=account_seed,
            account_grant=pin['account']['grantRef'], account_ref=pin['account']['accountRef'],
            account_public_key=pin['journal']['accountPublicKey'])
        self._resource = OrdinarySecretResource(self._admission, signer, custody_root=pin['custodyRoot'],
            plugin_identity=pin['pluginIdentityRef'], instance_id=pin['instanceId'], package_id=pin['packageId'])
        value = self._selection.policy
        for name, receiver in pin['receivers'].items():
            credential, seed = await self._file(load_receiver, self._selection, name)
            connection = await self._connect(name, credential)
            service = CapabilityReplyService(self._authority, resources=(self._resource,),
                hub_id=value['kernelScope']['hubId'], profile_id=value['kernelScope']['profileId'],
                authority_id=value['authorityId'], service_id=name+'-owner',
                service_identity_ref=receiver['serviceIdentityRef'], service_instance_id=receiver['serviceInstanceId'],
                signing_key_ref=receiver['issuer']['issuerRef'], signing_seed=seed,
                request_signing_key_ref=receiver['requestSigningKeyRef'], connection=connection)
            self._receivers.append(service)
            await service.start()
        await check_secret_authority(self._selection, self._identity)
        self._open()
        self._ready = True
        self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:
            raise ContractError('capability_secret_stale')
        self._starting = asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
        except asyncio.CancelledError:
            self.fence()
            raise
        except Exception as error:
            self.fence()
            raise SelectedStorageFailure('capability_secret_start_unconfirmed', self, error) from None

    def check_health(self):
        self._open()
        if (not self._ready or len(self._receivers) != 2 or self._resource is None
                or any(service._closed or service._subscription is None for service in self._receivers)
                or any(client.is_connected is not True for client in self._clients)):
            raise ContractError('capability_secret_stale')
        self._resource._current()

    def fence(self):
        self._closed, self._ready = True, False
        for service in self._receivers:
            service._closed = True

    async def _cleanup(self):
        if self._starting is not None:
            await asyncio.gather(self._starting, return_exceptions=True)
        for service in self._receivers:
            try:
                await service.close(timeout=10)
            except ContractError:
                if service._cleanup_task is None:
                    raise
                await asyncio.shield(service._cleanup_task)
        if self._resource is not None:
            await self._resource.close()
        if self._admission is not None:
            await self._admission.close()
        if self._verification is not None:
            await self._verification.close()
        if self._files:
            await asyncio.gather(*tuple(self._files), return_exceptions=True)
        for original in self._connects:
            await asyncio.gather(original, return_exceptions=True)
        for session in self._sessions:
            await session.close()
        for client in self._clients:
            await client.close()

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('capability_cleanup_invalid')
        if asyncio.get_running_loop() is not self._loop:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self)
        self.fence()
        if self._closing is None or self._closing.done() and (
                self._closing.cancelled() or self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._cleanup())
            self._closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            done, _ = await asyncio.wait({self._closing}, timeout=timeout)
            if not done:
                raise TimeoutError
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise SelectedStorageFailure('capability_cleanup_incomplete', self, error) from None
