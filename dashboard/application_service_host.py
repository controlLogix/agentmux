"""Run the fixed Python application services from admitted host enrollment.

The installed process owner supplies an ApplicationServiceSelection admitted
against its independent native host pins, and an actual lifetime stop event.
This module chooses no executable or profile and creates no credentials, streams,
buckets, backup keys or replacement processes. Package admission belongs to the
native process owner; dashboard imports use that package's approved module roots.
"""
import asyncio
import base64
import concurrent.futures
import uuid
import secrets
import threading

import nkeys
from agentmux_contracts import ContractError, canonical_bytes
from hub.nats_transport import new_client
from hub.fed.session import FederationSession
from identity.application_service_selection import ApplicationServiceSelection
from identity.service import IdentityService
from identity.legacy_identity import LegacyIdentityAdapter
from integration_owner.service import IntegrationRouterService, IntegrationService
from integration_owner.enrollment import load_atlassian_enrollment
from integration_owner.github_worker import load_github_enrollment
from native_security.nats_credentials import validate_service, validate_authority_switch_receiver
from state_owner.artifacts import OwnerArtifacts
from state_owner.backup_host import BackupHost
from state_owner.backup_lifecycle import OwnerBackupLifecycle
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import CheckpointReceipt
from state_owner.configuration_host import ConfigurationHost
from state_owner.task_host import TaskHost
from orchestration_owner.service import OrchestrationCommandService
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, owner_subject
from state_owner.authority_switch import AuthoritySwitchHost, AuthoritySwitchOwner
from state_owner.authority_switch_service import AuthoritySwitchService
from definition_command_service import DefinitionCommandService
from definition_commands import _joined, LocalDefinitionOutcomeUnconfirmed
from definition_service import DefinitionScope
from dashboard_commands import (DashboardCommandService, DashboardOutcomeUnconfirmed,
    SQLiteDashboardEffectOwner)
from dashboard_server_effects import DashboardServerEffects
import ccstore
from capability_owner.selected_storage import SelectedStorageHost
from capability_owner.policy_host import PolicyHost
from capability_owner.workspace_host import WorkspaceReadHost
from capability_owner.artifact_host import ArtifactReadHost
from local_browser_auth import LocalBrowserAuth
from oidc_browser_login import OIDCBrowserLogin
from identity.oidc_adapter import OIDCProvider
from identity.oidc_authorization_code import OIDCAuthorizationCodeProvider
from identity.oidc_device_authorization import OIDCDeviceAuthorizationProvider
from identity.oidc_terminal_login import OIDCTerminalLoginOwner


class ApplicationServiceFailure(RuntimeError):
    """Retain an exact lifecycle owner; never print private operation failures."""
    def __init__(self, code, owner, cause=None):
        super().__init__(code)
        self.owner, self._cause = owner, cause

    def __repr__(self):
        return f'ApplicationServiceFailure({str(self)!r})'


class ApplicationServiceHost:
    def __init__(self, selection, *, browser_port=0, browser_write_timeout=10):
        if not isinstance(selection, ApplicationServiceSelection):
            raise ContractError('application_service_selection_required')
        self._selection = selection
        self._authority_switch = selection.authority_switch_configuration()
        self._loop = asyncio.get_running_loop()
        self._startup = self._closing = None
        self._closed = self._ready = False
        self._services, self._clients, self._histories = [], [], []
        self._connects, self._checkpoints, self._sessions = [], {}, []
        self._connection_failure = None
        self._identity = self._definitions = self._integration = self._configuration = None
        self._federation_policy = None
        self._federation_policy_keys = []
        self._dashboard = None
        self._authority_switch_service = None
        self._integration_inventory = self._integration_route = None
        self._integration_seed = self._integration_credentials = None
        self._integration_client = self._integration_session = None
        self._integration_route_task = None
        self._integration_route_changed = asyncio.Event()
        self._integration_route_lock = asyncio.Lock()
        self._task = None
        self._orchestration = None
        self._storage = None
        self._policy_service = None
        self._workspace = None
        self._artifact = None
        self._secret_use = None
        self._process = None
        self._browser_auth = None
        self._oidc_settings = self._oidc_login = None
        self._oidc_terminal_settings = self._oidc_terminal = None
        # 8787 belongs to the old dashboard; the services host never takes it.
        if (type(browser_port) is not int or not 0 <= browser_port <= 65535 or browser_port == 8787
                or type(browser_write_timeout) not in (int, float)
                or not 0 < browser_write_timeout <= 10):
            raise ContractError('local_browser_auth_configuration')
        self._browser_port = browser_port
        self._browser_origin = None
        self._browser_server = self._browser_thread = None
        self._browser_write_timeout = browser_write_timeout

    def __repr__(self):
        return '<ApplicationServiceHost private>'

    def _open(self):
        if asyncio.get_running_loop() is not self._loop or self._closed:
            raise ContractError('application_service_host_closed')
        if self._connection_failure is not None:
            raise ContractError('application_service_connection_unavailable')

    def configure_local_browser_auth(self, auth):
        """Attach the one HTTP credential owner selected by the local host."""
        self._open()
        if not isinstance(auth, LocalBrowserAuth) or self._browser_auth is not None:
            raise ContractError('local_browser_auth_configuration')
        self._browser_auth = auth

    def configure_dashboard_commands(self, service):
        """Attach the protected dashboard owner; absence keeps mutations disabled."""
        self._open()
        if (not isinstance(service, DashboardCommandService)
                or self._identity is None or service._authority is not self._identity.reader
                or self._dashboard is not None):
            raise ContractError('dashboard_service_configuration')
        self._dashboard = service
        self._services.append(service)

    async def _start_dashboard_commands(self):
        """Open only the database pinned by the protected host selection."""
        selected = self._selection.dashboard_policy()
        if selected is None:
            return
        if selected['databasePath'] != str(ccstore.DB_PATH):
            raise ContractError('dashboard_service_configuration')

        def prepare():
            # Reuse the existing migration before pinning the exact resulting
            # file identity. Later replacement, linking or path changes fail.
            with ccstore.connection():
                pass
            return ccstore.DB_PATH.stat()

        info = await _joined(prepare)
        effects = SQLiteDashboardEffectOwner(ccstore.DB_PATH,
            device=info.st_dev, inode=info.st_ino, owner_uid=info.st_uid,
            effects=DashboardServerEffects('127.0.0.1'))
        service = DashboardCommandService(self._identity.reader,
            scope=selected['scope'], resource_ref=selected['resourceRef'],
            effects=effects)
        self.configure_dashboard_commands(service)

    def _browser(self):
        self._open()
        if self._browser_auth is None:
            raise ContractError('local_browser_auth_unavailable')
        return self._browser_auth

    def configure_oidc_browser(self, provider, authorization_endpoint, token_endpoint):
        """Attach only protected host configuration, before the HTTP owner starts."""
        self._open()
        if (type(provider) is not OIDCProvider
                or not all(isinstance(value, str)
                    for value in (authorization_endpoint, token_endpoint))
                or self._oidc_settings is not None or self._browser_server is not None):
            raise ContractError('oidc_browser_configuration_invalid')
        self._oidc_settings = (provider, authorization_endpoint, token_endpoint)

    def configure_oidc_terminal(self, provider, device_endpoint, token_endpoint):
        """Attach protected device configuration before identity startup."""
        self._open()
        if (type(provider) is not OIDCProvider
                or not all(isinstance(value, str)
                    for value in (device_endpoint, token_endpoint))
                or self._oidc_terminal_settings is not None or self._startup is not None):
            raise ContractError('oidc_terminal_configuration_invalid')
        self._oidc_terminal_settings = (provider, device_endpoint, token_endpoint)

    async def approve_local_browser(self, challenge, session, authority, *, origin=None):
        """Called by the fixed signed owner-command receiver after admission."""
        self._open()
        return await self._browser().approve_pairing(
            challenge, session, authority, origin=origin)

    def _start_local_browser(self):
        """Start the one same-process loopback server owned by this host."""
        self._open()
        if self._browser_server is not None:
            raise ContractError('local_browser_auth_configuration')
        from server import BacklogServer, Handler
        server = BacklogServer(('127.0.0.1', self._browser_port), Handler,
                               application_host=self)
        port = server.server_address[1]
        auth = LocalBrowserAuth(port)
        self.configure_local_browser_auth(auth)
        self._browser_origin = f'http://127.0.0.1:{port}'
        if self._oidc_settings is not None:
            provider, authorization_endpoint, token_endpoint = self._oidc_settings
            configuration = OIDCAuthorizationCodeProvider(provider,
                authorization_endpoint, token_endpoint,
                self._browser_origin + '/api/local-auth/oidc/callback')
            self._oidc_login = OIDCBrowserLogin(configuration, self._identity, auth,
                self._selection.service('definitions')['ledger']['scope'],
                self._browser_origin)
        thread = threading.Thread(target=server.serve_forever,
            name='agentmux-local-dashboard', daemon=False)
        self._browser_server, self._browser_thread = server, thread
        thread.start()

    def _from_http_thread(self, coroutine, timeout, *, uncertain_operation_id=None,
                          uncertain_factory=None):
        if self._closed or not self._loop.is_running():
            coroutine.close()
            raise ContractError('application_service_host_unavailable')
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout)
        except ContractError:
            raise
        except concurrent.futures.TimeoutError:
            if uncertain_operation_id is not None:
                # The event-loop owner retains and completes this exact operation.
                # A timed-out HTTP waiter may reconcile it but may not replace it.
                def consume(completed):
                    try:
                        completed.exception()
                    except BaseException:
                        pass
                future.add_done_callback(consume)
                if uncertain_factory is not None:
                    raise uncertain_factory(uncertain_operation_id) from None
                raise LocalDefinitionOutcomeUnconfirmed(
                    'definition_outcome_unconfirmed', uncertain_operation_id) from None
            future.cancel()
            raise ContractError('application_service_host_unavailable') from None
        except BaseException:
            future.cancel()
            raise

    def browser_pair(self, challenge, *, method, target, host, origin):
        """Bridge one bounded HTTP handler thread to this owner's event loop."""
        async def wait():
            return await self._browser().pair(challenge, method=method,
                target=target, host=host, origin=origin)
        return self._from_http_thread(wait(), 31)

    def browser_logout(self, cookie, csrf, *, method, target, host, origin):
        async def logout():
            return self._browser().logout(cookie, csrf, method=method, target=target,
                host=host, origin=origin)
        return self._from_http_thread(logout(), 2)

    def browser_oidc_start(self, *, method, target, host, origin):
        async def begin():
            self._open()
            if self._oidc_login is None:
                raise ContractError('oidc_browser_not_configured')
            return self._oidc_login.begin(method=method, target=target,
                                          host=host, origin=origin)
        return self._from_http_thread(begin(), 2)

    def browser_oidc_callback(self, target, cookie, *, method, host):
        async def complete():
            self._open()
            if self._oidc_login is None:
                raise ContractError('oidc_browser_not_configured')
            return await self._oidc_login.complete(target, cookie,
                                                   method=method, host=host)
        return self._from_http_thread(complete(), 10)

    def browser_definition(self, cookie, csrf, *, method, target, host, origin, body):
        operation_id = 'browser_' + uuid.uuid4().hex
        async def execute():
            context = await self._browser().authorize(cookie, csrf, method=method,
                target=target, host=host, origin=origin, body=body)
            return await self._definitions.handle_local_browser(
                context, target, body, operation_id=operation_id)
        return self._from_http_thread(execute(), self._browser_write_timeout,
                                      uncertain_operation_id=operation_id)

    def browser_dashboard_command(self, cookie, csrf, *, method, target, host,
                                  origin, body):
        operation_id = 'dashboard_' + secrets.token_hex(32)
        async def execute():
            self._open()
            if self._dashboard is None:
                raise ContractError('dashboard_service_unavailable')
            context = await self._browser().authenticate_dashboard(cookie, csrf,
                method=method, target=target, host=host, origin=origin)
            return await self._dashboard.handle_local_browser(context, target, body,
                operation_id=operation_id)
        return self._from_http_thread(execute(), self._browser_write_timeout,
            uncertain_operation_id=operation_id,
            uncertain_factory=DashboardOutcomeUnconfirmed)

    async def _lost(self):
        self._connection_failure = 'application_service_connection_unavailable'
        # Ending application binding does not claim a completed business effect.
        self.fence()

    async def _quiet_error(self, _error):
        # Keep broker and authentication diagnostics in their private owners.
        self._connection_failure = 'application_service_connection_unavailable'
        self.fence()

    def _policy(self, role):
        if role == 'authority-switch':
            return self._selection.authority_switch_policy_inputs()
        return self._selection.service_policy_inputs(role)

    async def _connect(self, role, *, routed_credential=None):
        if role == 'federation-policy':
            selected = self._selection.policy['federationPolicy']['service']
        elif role in ('workspace', 'artifact'):
            selected = self._selection.policy[role]['receiver']
        elif role == 'authority-switch':
            binding = self._selection.policy['authoritySwitch']['binding']
            if binding is None:
                raise ContractError('application_service_credential_binding')
            selected = binding['receiver']
        else:
            selected = self._selection.service(role)
        if routed_credential is None:
            if role == 'federation-policy':
                from identity.federation_policy_selection import load_policy_credentials
                admitted = await _joined(load_policy_credentials, self._selection)
            elif role == 'workspace':
                from identity.workspace_selection import load_workspace_credentials
                admitted = await _joined(load_workspace_credentials, self._selection)
            elif role == 'artifact':
                from identity.artifact_selection import load_artifact_credentials
                admitted = await _joined(load_artifact_credentials, self._selection)
            elif role == 'authority-switch':
                raw = await _joined(self._selection.read_authority_switch_credentials)
                admitted = validate_authority_switch_receiver(raw,
                    account_public_key=selected['credentials']['accountPublicKey'],
                    **self._policy(role))
            else:
                raw = await _joined(self._selection.read_credential_bytes, role)
                admitted = validate_service(raw,
                    account_public_key=selected['credentials']['accountPublicKey'],
                    **self._policy(role))
            if admitted.public_key != selected['credentials']['userPublicKey']:
                raise ContractError('application_service_credential_binding')
        else:
            if role != 'integration':
                raise ContractError('application_service_credential_binding')
            admitted = routed_credential
        self._open()
        client = new_client(require_tls=True,
            leaf_certificate_sha256=selected['connection']['leafCertificateSHA256'])
        self._clients.append(client)
        # Reuse the existing allocation-time subscription/task owner. It is a
        # resource lifetime helper and supplies no federation or business grant.
        session = FederationSession()
        self._sessions.append(session)
        client._agentmux_session = session

        def signature(nonce):
            key = nkeys.from_seed(admitted.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode()))
            finally:
                key.wipe()

        if role == 'federation-policy':
            from identity.federation_policy_selection import policy_tls_options
            options = policy_tls_options(self._selection)
        elif role == 'workspace':
            from identity.workspace_selection import workspace_tls_options
            options = workspace_tls_options(self._selection)
        elif role == 'artifact':
            from identity.artifact_selection import artifact_tls_options
            options = artifact_tls_options(self._selection)
        else:
            options = (self._selection.authority_switch_tls_options()
                       if role == 'authority-switch' else self._selection.tls_options(role))
        async def lost():
            if not getattr(client, '_agentmux_expected_close', False):
                await self._lost()

        async def quiet(_error):
            if not getattr(client, '_agentmux_expected_close', False):
                await self._quiet_error(_error)

        options.update(name='agentmux-' + role + '-service', allow_reconnect=False,
            max_reconnect_attempts=1, reconnect_time_wait=0, connect_timeout=3,
            dont_randomize=True, no_echo=True, inbox_prefix=selected['credentials']['replyPrefix'],
            user_jwt_cb=lambda: admitted.jwt.encode(), signature_cb=signature,
            disconnected_cb=lost, reconnected_cb=lost, closed_cb=lost,
            error_cb=quiet)
        connect = asyncio.create_task(client.connect(**options))
        self._connects.append(connect)
        async with asyncio.timeout(5):
            await connect
        self._open()
        if client.is_connected is not True:
            raise ContractError('application_service_connection_unavailable')
        return client

    async def _resources(self, role):
        selected = self._selection.service(role)
        ledger = selected['ledger']
        history = OwnerHistory(ledger['history']['path'], self._selection.binding(role),
            stream_identity=self._selection.stream_identity(role),
            max_records=ledger['history']['maxRecords'], max_bytes=ledger['history']['maxBytes'])
        self._histories.append(history)
        checkpoint = await _joined(lambda: CheckpointHost(ledger['checkpoint']['path'],
            stream=ledger['stream'], commit_ref=ledger['checkpoint']['commitRef'],
            binding=self._selection.binding(role), stream_identity=self._selection.stream_identity(role),
            max_records=ledger['history']['maxRecords'], max_bytes=ledger['history']['maxBytes']))
        self._checkpoints[role] = checkpoint
        self._open()
        # Identity's older receipt wrapper carries these same closed fields.
        # The concrete host still checks exact path, commitRef, stream and bytes.
        async def committed(receipt):
            return await checkpoint.committed(CheckpointReceipt(receipt.manifest_path, receipt.digest, receipt.cursor))
        return history, checkpoint, committed

    async def _start(self):
        self._open()
        selected = self._selection.service('identity')
        seed = await _joined(self._selection.load_signing_seed, 'identity')
        backup = selected['backup']
        backup_host = await _joined(lambda: BackupHost(
            *(backup[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self._selection.binding('identity'),
            stream_identity=self._selection.stream_identity('identity')))
        await _joined(backup_host.load_key, backup['keyId'])
        self._open()
        identity_connection = await self._connect('identity')
        history, checkpoint, committed = await self._resources('identity')
        identity = IdentityService(identity_connection, **self._selection.identity_kwargs(history=history,
            checkpoint_committed=committed, signing_seed=seed, backup_host=backup_host))
        self._identity = identity
        self._services.append(identity)
        identity.configure_legacy_identity(LegacyIdentityAdapter(identity.reader,
            local_source_hub_id=self._selection.policy['kernelScope']['hubId'],
            scope=self._selection.service('definitions')['ledger']['scope']))
        identity.ledger.require_recovery_identity(await checkpoint.recovery_identity())
        self._open()
        await identity.start()
        self._open()
        if self._authority_switch is not None:
            await self._start_authority_switch()
            self._open()
        if self._oidc_terminal_settings is not None:
            provider, device_endpoint, token_endpoint = self._oidc_terminal_settings
            configuration = OIDCDeviceAuthorizationProvider(
                provider, device_endpoint, token_endpoint)
            terminal = OIDCTerminalLoginOwner(configuration, identity)
            self._oidc_terminal = terminal
            identity.configure_oidc_terminal(terminal)

        selected = self._selection.service('definitions')
        seed = await _joined(self._selection.load_signing_seed, 'definitions')
        connection = await self._connect('definitions')
        history, checkpoint, committed = await self._resources('definitions')
        domain = selected['connection']['jetstreamDomain']
        jetstream = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        store = await jetstream.object_store(selected['artifacts']['bucket'])
        self._open()
        artifacts = OwnerArtifacts(store, jetstream, bucket=selected['artifacts']['bucket'],
            owner_hub_id=self._selection.policy['kernelScope']['hubId'],
            store_ref=selected['artifacts']['storeRef'], max_bytes=selected['artifacts']['maxBytes'])
        roots = selected['directories']
        scope = DefinitionScope(roots['projectRoot'], roots['home'], roots['globalRoot'],
                                selected['ledger']['scope']['projectId'])
        definitions = DefinitionCommandService.from_enrolled_host(connection,
            **self._selection.definition_kwargs(history=history, checkpoint_committed=committed,
                signing_seed=seed, authority=identity.reader, artifacts=artifacts, scope=scope))
        self._definitions = definitions
        self._services.append(definitions)
        definitions.ledger.require_recovery_identity(await checkpoint.recovery_identity())
        self._open()
        await definitions.start()
        self._open()
        if self._selection.orchestration_policy() is not None:
            await self._start_orchestration()
            self._open()
        await self._start_dashboard_commands()
        self._open()
        self._start_local_browser()
        self._identity.configure_local_browser_host(self)
        self._open()
        if self._selection.policy.get('integration') is not None:
            await self._start_integration()
            self._open()
        if self._selection.policy.get('configuration') is not None:
            await self._start_configuration()
            self._open()
        if self._selection.policy.get('task') is not None:
            await self._start_task()
            self._open()
        if self._selection.policy.get('federationPolicy') is not None:
            await self._start_federation_policy()
            self._open()
        if self._selection.policy.get('storage') is not None:
            storage = (SelectedStorageHost(self._selection, identity=self._identity,
                federation_policy=self._federation_policy) if self._selection.policy.get('federationPolicy') is not None
                else SelectedStorageHost(self._selection, identity=self._identity))
            self._storage = storage
            self._services.append(storage)
            await storage.start()
            self._open()
        if self._selection.policy.get('policy') is not None:
            await self._start_policy()
            self._open()
        if self._selection.policy.get('workspace') is not None:
            await self._start_workspace()
            self._open()
        if self._selection.policy.get('artifact') is not None:
            await self._start_artifact()
            self._open()
        if self._selection.policy.get('ordinarySecret') is not None:
            from capability_owner.secret_host import SecretUseHost
            self._secret_use = SecretUseHost(self._selection, identity=self._identity)
            self._services.append(self._secret_use)
            await self._secret_use.start()
            self._open()
        if self._selection.policy.get('process') is not None:
            from capability_owner.process_host import ProcessHost
            self._process = ProcessHost(self._selection, identity=self._identity,
                task=self._task, workspace=self._workspace)
            self._services.append(self._process)
            await self._process.start()
            self._open()
        self._ready = True

    async def _start_orchestration(self):
        selected = self._selection.service('orchestration')
        seed = await _joined(self._selection.load_signing_seed, 'orchestration')
        phase_seed = await _joined(self._selection.load_orchestration_phase_seed)
        await self._selection.check_orchestration_authority(self._identity)
        self._open()
        connection = await self._connect('orchestration')
        self._open()
        # This owner rebuilds its index from the retained journal. Its factory
        # has no checkpoint callback; do not create an unused checkpoint owner.
        ledger = selected['ledger']
        history = OwnerHistory(ledger['history']['path'],
            self._selection.binding('orchestration'),
            stream_identity=self._selection.stream_identity('orchestration'),
            max_records=ledger['history']['maxRecords'],
            max_bytes=ledger['history']['maxBytes'])
        self._histories.append(history)
        service = OrchestrationCommandService.from_enrolled_host(connection,
            **self._selection.orchestration_kwargs(authority=self._identity.reader,
                ingress=self._identity.ingress,
                history=history, signing_seed=seed, phase_signing_seed=phase_seed))
        self._orchestration = service
        self._services.append(service)
        await service.start()
        self._open()
        # History preparation may have waited on the broker. Recheck current
        # authority before publishing application readiness.
        await self._selection.check_orchestration_authority(self._identity)
        self._open()

    async def _start_artifact(self):
        from identity.artifact_selection import load_artifact_signing_seed
        seed = await _joined(load_artifact_signing_seed, self._selection)
        connection = await self._connect('artifact')
        service = ArtifactReadHost(self._selection, identity=self._identity,
            task=self._task, connection=connection, signing_seed=seed)
        self._artifact = service
        self._services.append(service)
        await service.start()
        self._open()

    async def _start_workspace(self):
        from identity.workspace_selection import load_workspace_signing_seed
        seed = await _joined(load_workspace_signing_seed, self._selection)
        connection = await self._connect('workspace')
        sources = []
        if self._storage is not None:
            if self._storage._audit is not None:
                sources.append(self._storage._audit)
            sources.extend(self._storage._message_stores)
        service = WorkspaceReadHost(self._selection, identity=self._identity,
            task=self._task, connection=connection, signing_seed=seed,
            borrowed_sources=sources)
        self._workspace = service
        self._services.append(service)
        await service.start()
        self._open()

    async def _start_policy(self):
        selected = self._selection.service('policy')
        seed = await _joined(self._selection.load_signing_seed, 'policy')
        backup = selected['backup']
        host = await _joined(lambda: BackupHost(
            *(backup[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self._selection.binding('policy'),
            stream_identity=self._selection.stream_identity('policy')))
        await _joined(host.load_key, backup['keyId'])
        self._open()
        connection = await self._connect('policy')
        history, checkpoint, _ = await self._resources('policy')
        service = PolicyHost(self._selection, identity=self._identity, connection=connection,
            history=history, checkpoint_host=checkpoint, backup_host=host, signing_seed=seed)
        self._policy_service = service
        self._services.append(service)
        await service.start()
        self._open()

    async def _start_authority_switch(self):
        """Start the retained switch owner without exposing its ledger credential."""
        selected = self._selection.policy['authoritySwitch']
        binding_value = selected['binding']
        if binding_value is None or self._identity is None:
            raise ContractError('authority_switch_service_configuration')
        receiver, ledger_value = binding_value['receiver'], binding_value['ledger']
        seed = await _joined(self._selection.load_authority_switch_signing_seed)
        connection = await self._connect('authority-switch')
        # The public guard keeps no ledger credentials. Build the private owner
        # from the same protected selection and retained custody directory.
        from state_owner.ledger import OwnerBinding, StreamIdentity
        from state_owner.retention import Retention
        from datetime import datetime
        binding = OwnerBinding(self._selection.policy['kernelScope']['hubId'],
            'authority-switch', binding_value['switchId'], 'authority-switch',
            canonical_bytes(ledger_value['scope']))
        stream_value = ledger_value['streamIdentity']
        stream_identity = StreamIdentity(datetime.fromisoformat(stream_value['created']),
                                         stream_value['minimumSequence'])
        history = OwnerHistory(ledger_value['history']['path'], binding,
            stream_identity=stream_identity,
            max_records=ledger_value['history']['maxRecords'],
            max_bytes=ledger_value['history']['maxBytes'])
        self._histories.append(history)
        checkpoint = await _joined(lambda: CheckpointHost(ledger_value['checkpoint']['path'],
            stream=ledger_value['stream'], commit_ref=ledger_value['checkpoint']['commitRef'],
            binding=binding, stream_identity=stream_identity,
            max_records=ledger_value['history']['maxRecords'],
            max_bytes=ledger_value['history']['maxBytes']))
        self._checkpoints['authority-switch'] = checkpoint
        domain = receiver['connection']['jetstreamDomain']
        jetstream = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        retention = ledger_value['retention']
        ledger = OwnerLedger(jetstream, stream=ledger_value['stream'],
            subject=owner_subject(binding), binding=binding,
            retention=Retention(retention['maxBytes'], retention['reserveBytes'],
                                retention['replicas']),
            stream_identity=stream_identity, history=history)
        ledger.require_recovery_identity(await checkpoint.recovery_identity())
        host = AuthoritySwitchHost(selected['custodyDirectory'], binding=binding,
                                   stream_identity=stream_identity)
        owner = AuthoritySwitchOwner(self._identity.reader, ledger, host=host)
        service = AuthoritySwitchService(owner, self._identity.ingress,
            connection=connection,
            profile_id=self._selection.policy['kernelScope']['profileId'],
            authority_id=self._selection.policy['authorityId'],
            service_identity_ref=receiver['serviceIdentityRef'],
            service_instance_id=receiver['serviceInstanceId'],
            signing_key_ref=receiver['issuer']['issuerRef'], signing_seed=seed)
        self._authority_switch_service = service
        self._services.append(service)
        await service.start()

    async def _start_task(self):
        selected = self._selection.service('task')
        seed = await _joined(self._selection.load_signing_seed, 'task')
        backup = selected['backup']
        backup_host = await _joined(lambda: BackupHost(
            *(backup[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self._selection.binding('task'),
            stream_identity=self._selection.stream_identity('task')))
        await _joined(backup_host.load_key, backup['keyId'])
        self._open()
        connection = await self._connect('task')
        history, checkpoint, _ = await self._resources('task')
        artifacts = None
        if selected.get('artifacts') is not None:
            pin = selected['artifacts']
            domain = selected['connection']['jetstreamDomain']
            jetstream = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
            store = await jetstream.object_store(pin['bucket'])
            self._open()
            artifacts = OwnerArtifacts(store, jetstream, bucket=pin['bucket'],
                owner_hub_id=self._selection.binding('task').hub_id,
                store_ref=pin['storeRef'], max_bytes=pin['maxBytes'])
        task = TaskHost.from_enrolled_host(connection,
            **self._selection.task_kwargs(authority=self._identity.reader, ingress=self._identity.ingress,
                history=history, signing_seed=seed, checkpoint_host=checkpoint,
                backup_host=backup_host, artifacts=artifacts))
        self._task = task
        self._services.append(task)
        self._open()
        await task.start()
        self._open()

    async def _start_federation_policy(self):
        from datetime import datetime
        from identity.federation_policy_selection import (check_federation_policy_selection,
            policy_binding, policy_target, load_policy_seed, policy_event_producer, check_policy_authority)
        from state_owner.federation_policy import (FederationPolicyCustody,
            SCHEMA_REF, FEDERATION_POLICY_SCHEMA)
        from state_owner.conversation_migration import ConversationKey
        from state_owner.ledger import StreamIdentity
        from state_owner.retention import Retention
        value = self._selection.policy
        check_federation_policy_selection(value)
        selected = value['federationPolicy']
        service, binding = selected['service'], policy_binding(value)
        ledger, backup = service['ledger'], service['backup']
        stream_identity = StreamIdentity(datetime.fromisoformat(ledger['streamIdentity']['created']),
            ledger['streamIdentity']['minimumSequence'])
        seed = await _joined(load_policy_seed, self._selection)
        await check_policy_authority(self._selection, self._identity, seed)
        self._open()
        key = ConversationKey(selected['key']['path'], key_ref=selected['key']['keyRef'])
        self._federation_policy_keys.append(key)
        history = OwnerHistory(ledger['history']['path'], binding, stream_identity=stream_identity,
            max_records=ledger['history']['maxRecords'], max_bytes=ledger['history']['maxBytes'])
        self._histories.append(history)
        checkpoint = CheckpointHost(ledger['checkpoint']['path'], stream=ledger['stream'],
            commit_ref=ledger['checkpoint']['commitRef'], binding=binding, stream_identity=stream_identity,
            max_records=ledger['history']['maxRecords'], max_bytes=ledger['history']['maxBytes'])
        self._checkpoints['federation-policy'] = checkpoint
        backup_host = BackupHost(*(backup[k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')),
            destination_id=backup['destinationId'], binding=binding, stream_identity=stream_identity)
        await _joined(backup_host.load_key, backup['keyId'])
        self._open()
        connection = await self._connect('federation-policy')
        domain = service['connection']['jetstreamDomain']
        js = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        artifacts = selected['artifacts']
        store = await js.object_store(artifacts['bucket'])
        self._open()
        owned_artifacts = OwnerArtifacts(store, js, bucket=artifacts['bucket'],
            owner_hub_id=value['kernelScope']['hubId'], store_ref=artifacts['storeRef'], max_bytes=artifacts['maxBytes'])
        custody = FederationPolicyCustody(policy_target(value), owned_artifacts, key,
            ingress=self._identity.ingress, backup_transport_ref=selected['backupAuthority']['transportRef'],
            backup_grant_ref=selected['backupAuthority']['grantRef'])
        retention = ledger['retention']
        host = ConfigurationHost.from_enrolled_host(connection, authority=self._identity.reader,
            stream=ledger['stream'], binding=binding, stream_identity=stream_identity,
            retention=Retention(retention['maxBytes'],retention['reserveBytes'],retention['replicas']),
            history=history, owner=service['owner'], schema_ref=SCHEMA_REF,
            schema_resources={SCHEMA_REF:FEDERATION_POLICY_SCHEMA}, issuer_ref=service['issuer']['issuerRef'],
            signing_seed=seed, reply_prefix=service['requesterReplyPrefix'], checkpoint_host=checkpoint,
            backup_host=backup_host, backup_key_id=backup['keyId'],
            jetstream_domain=domain, event_account_public_key=service['credentials']['accountPublicKey'],
            event_jetstream_domain=domain, event_producer=policy_event_producer(self._selection,self._identity.reader,seed),
            federation_policy=custody)
        self._federation_policy = host
        self._services.append(host)
        self._open()
        await host.start()
        self._open()

    async def _start_configuration(self):
        selected = self._selection.service('configuration')
        seed = await _joined(self._selection.load_signing_seed, 'configuration')
        backup = selected['backup']
        backup_host = await _joined(lambda: BackupHost(
            *(backup[key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')),
            destination_id=backup['destinationId'], binding=self._selection.binding('configuration'),
            stream_identity=self._selection.stream_identity('configuration')))
        await _joined(backup_host.load_key, backup['keyId'])
        self._open()
        connection = await self._connect('configuration')
        history, checkpoint, _ = await self._resources('configuration')
        configuration = ConfigurationHost.from_enrolled_host(connection,
            **self._selection.configuration_kwargs(authority=self._identity.reader, history=history,
                signing_seed=seed, checkpoint_host=checkpoint, backup_host=backup_host))
        self._configuration = configuration
        # Retain the original owner before startup can allocate subscriptions.
        self._services.append(configuration)
        self._open()
        await configuration.start()
        self._open()

    async def _start_integration(self):
        selected = self._selection.service('integration')
        seed = await _joined(self._selection.load_signing_seed, 'integration')
        credentials = None
        if selected['provider'] in ('jira', 'confluence'):
            raw = await _joined(self._selection.read_integration_enrollment)
            credentials = await _joined(lambda: load_atlassian_enrollment(raw,
                credential_ref=selected['credentialRef'], provider=selected['provider']))
        elif selected['provider'] == 'github' and selected['credentialEnrollment'] is not None:
            raw = await _joined(self._selection.read_integration_enrollment)
            credentials = await _joined(lambda: load_github_enrollment(raw,
                credential_ref=selected['credentialRef']))
        self._open()
        if selected.get('routing') is not None:
            inventory = await _joined(self._selection.integration_effect_inventory)
            route = await _joined(inventory.current_route)
            self._integration_inventory = inventory
            self._integration_seed, self._integration_credentials = seed, credentials
            await self._activate_integration_route(route)
            self._integration_route_task = asyncio.create_task(
                self._watch_integration_route())
            return
        connection = await self._connect('integration')
        history, checkpoint, committed = await self._resources('integration')
        domain = selected['connection']['jetstreamDomain']
        jetstream = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        store = await jetstream.object_store(selected['artifacts']['bucket'])
        self._open()
        artifacts = OwnerArtifacts(store, jetstream, bucket=selected['artifacts']['bucket'],
            owner_hub_id=self._selection.policy['kernelScope']['hubId'],
            store_ref=selected['artifacts']['storeRef'], max_bytes=selected['artifacts']['maxBytes'])
        integration = IntegrationService.from_enrolled_host(connection,
            **self._selection.integration_kwargs(authority=self._identity.reader,
                history=history, artifacts=artifacts, credentials=credentials,
                signing_seed=seed, checkpoint_committed=committed),
            session_authorizer=(self._identity.authorize_oidc_terminal
                if self._oidc_terminal is not None else None))
        self._integration = integration
        self._services.append(integration)
        integration.ledger.require_recovery_identity(await checkpoint.recovery_identity())
        self._open()
        await integration.start()
        self._open()

    async def _activate_integration_route(self, route):
        """Start one complete preprovisioned route generation."""
        selected = self._selection.service('integration')
        seed, credentials = self._integration_seed, self._integration_credentials
        connection = await self._connect('integration',
                                         routed_credential=route.credential)
        session = connection._agentmux_session
        domain = selected['connection']['jetstreamDomain']
        jetstream = connection.jetstream() if domain is None else connection.jetstream(domain=domain)
        store = await jetstream.object_store(selected['artifacts']['bucket'])
        self._open()
        artifacts = OwnerArtifacts(store, jetstream,
            bucket=selected['artifacts']['bucket'],
            owner_hub_id=self._selection.policy['kernelScope']['hubId'],
            store_ref=selected['artifacts']['storeRef'],
            max_bytes=selected['artifacts']['maxBytes'])

        async def service_factory(binding, original_operation_id):
            current = await _joined(self._integration_inventory.current_route)
            if current.generation != route.generation:
                self._integration_route_changed.set()
                raise ContractError('integration_route_generation_changed')
            # OwnerHistory is thread-affine; construct it on this event-loop
            # owner just like the fixed-role resource path.
            resources = self._integration_inventory.open_effect(
                binding, original_operation_id, route=route)
            self._histories.append(resources.history)
            self._checkpoints['integration:' + binding.entity_id] = resources.checkpoint

            async def committed(receipt):
                return await resources.checkpoint.committed(CheckpointReceipt(
                    receipt.manifest_path, receipt.digest, receipt.cursor))

            try:
                backup_lifecycle = OwnerBackupLifecycle(resources.history,
                    resources.binding, resources.stream_identity, resources.backup,
                    key_id=selected['routing']['backupKeyId'],
                    retrieve_artifact=artifacts.retrieve)
                service = IntegrationService.from_enrolled_host(connection,
                    authority=self._identity.reader, binding=resources.binding,
                    provider=selected['provider'],
                    credential_ref=selected['credentialRef'],
                    stream=resources.stream,
                    stream_identity=resources.stream_identity,
                    retention=self._selection.retention('integration'),
                    history=resources.history, artifacts=artifacts,
                    issuer_ref=selected['issuer']['issuerRef'], signing_seed=seed,
                    checkpoint_path=resources.checkpoint.checkpoint_prefix,
                    checkpoint_committed=committed, credentials=credentials,
                    jetstream_domain=domain, backup_lifecycle=backup_lifecycle,
                    session_authorizer=(self._identity.authorize_oidc_terminal
                        if self._oidc_terminal is not None else None))
                service.ledger.require_recovery_identity(
                    await resources.checkpoint.recovery_identity())
                return service
            except BaseException:
                resources.history.close()
                raise

        router = IntegrationRouterService.from_enrolled_host(connection,
            **self._selection.integration_router_kwargs(
                authority=self._identity.reader, signing_seed=seed,
                service_factory=service_factory, artifacts=artifacts,
                credentials=credentials),
            session_authorizer=(self._identity.authorize_oidc_terminal
                if self._oidc_terminal is not None else None))
        self._integration = router
        self._services.append(router)
        try:
            await router.start()
        except BaseException:
            await router.close()
            self._services.remove(router)
            self._integration = None
            connection._agentmux_expected_close = True
            await session.close()
            await connection.close()
            raise
        self._integration_route = route
        self._integration_client = connection
        self._integration_session = session
        self._open()

    async def _retire_integration_route(self):
        router, client, session = (self._integration, self._integration_client,
                                   self._integration_session)
        if router is not None:
            await router.close()
            if router in self._services:
                self._services.remove(router)
        if session is not None:
            await session.close()
            if session in self._sessions:
                self._sessions.remove(session)
        if client is not None:
            client._agentmux_expected_close = True
            await client.close()
            if client in self._clients:
                self._clients.remove(client)
        self._integration = self._integration_client = self._integration_session = None

    async def _refresh_integration_route(self):
        async with self._integration_route_lock:
            route = await _joined(self._integration_inventory.current_route)
            if (self._integration_route is not None
                    and route.generation == self._integration_route.generation):
                return False
            await self._retire_integration_route()
            await self._activate_integration_route(route)
            return True

    async def _watch_integration_route(self):
        try:
            while not self._closed:
                try:
                    await asyncio.wait_for(self._integration_route_changed.wait(), 30)
                except asyncio.TimeoutError:
                    pass
                self._integration_route_changed.clear()
                if not self._closed:
                    await self._refresh_integration_route()
        except asyncio.CancelledError:
            raise
        except Exception:
            self._connection_failure = 'application_service_connection_unavailable'
            self.fence()

    async def start(self):
        self._open()
        if self._startup is not None:
            raise ContractError('application_service_host_started')
        self._startup = asyncio.create_task(self._start())
        try:
            await asyncio.shield(self._startup)
        except BaseException as error:
            raise ApplicationServiceFailure('application_service_start_unconfirmed', self, error) from None

    def check_health(self):
        self._open()
        if not self._ready:
            raise ContractError('application_service_host_unavailable')
        self._identity.check_health()
        if self._integration is not None:
            self._integration.check_health()
        if self._configuration is not None:
            self._configuration.check_health()
        if self._federation_policy is not None:
            self._federation_policy.check_health()
        if self._task is not None:
            self._task.check_health()
        if self._orchestration is not None:
            self._orchestration.check_health()
        if self._storage is not None:
            self._storage.check_health()
        if self._policy_service is not None:
            self._policy_service.check_health()
        if self._workspace is not None:
            self._workspace.check_health()
        if self._artifact is not None:
            self._artifact.check_health()
        if self._secret_use is not None:
            self._secret_use.check_health()
        if self._process is not None:
            self._process.check_health()
        if self._definitions._closed:
            raise ContractError('application_service_host_unavailable')
        for task in (self._definitions._checkpoint_task, self._definitions._checkpoint_work):
            if task is not None and task.done():
                task.result()

    async def _close(self):
        if self._startup is not None:
            if not self._startup.done():
                self._startup.cancel()
            try:
                await self._startup
            except BaseException:
                pass  # The startup result remains in its exact original task.
        failures = []
        if self._oidc_terminal is not None:
            try:
                await self._oidc_terminal.close()
            except BaseException as error:
                failures.append(error)
        if self._oidc_login is not None:
            try:
                await self._oidc_login.close()
            except BaseException as error:
                failures.append(error)
        if self._integration_route_task is not None:
            self._integration_route_task.cancel()
            try:
                await self._integration_route_task
            except asyncio.CancelledError:
                pass
            except BaseException as error:
                failures.append(error)
            self._integration_route_task = None
        if self._browser_server is not None:
            server, thread = self._browser_server, self._browser_thread
            try:
                await asyncio.to_thread(server.shutdown)
                server.server_close()
                await asyncio.to_thread(thread.join, 2)
                if thread.is_alive():
                    raise ContractError('local_browser_server_cleanup_pending')
            except BaseException as error:
                failures.append(error)
            finally:
                self._browser_server = self._browser_thread = None
        for service in reversed(self._services):
            try:
                try:
                    if isinstance(service, (ConfigurationHost, TaskHost, SelectedStorageHost, PolicyHost, WorkspaceReadHost, ArtifactReadHost)):
                        # The aggregate close task owns the bounded public wait.
                        # Join this exact owner close before releasing
                        # its borrowed history and transport, including retries.
                        await service.close(timeout=None)
                    else:
                        await service.close()
                except TimeoutError:
                    # Public close bounded its caller, not the original drain.
                    # Keep that exact join inside our retained aggregate task.
                    await asyncio.shield(service._drain_task)
            except BaseException as error:
                failures.append(error)
                # Earlier services include the identity reader borrowed by this
                # owner. Retain them until this exact cleanup can be joined.
                break
        # A service close timeout retains its original join. Do not close its
        # history or transport underneath workers that have not finished.
        if failures:
            raise BaseExceptionGroup('private application service cleanup', failures)
        for key in self._federation_policy_keys:
            key.close()
        for connect in self._connects:
            if not connect.done():
                connect.cancel()
            try:
                await connect
            except BaseException:
                pass
        for session in reversed(self._sessions):
            try:
                try:
                    await session.close()
                except Exception:
                    if session.close_task is None:
                        raise
                    await asyncio.shield(session.close_task)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup('private application subscription cleanup', failures)
        for client in reversed(self._clients):
            tasks = tuple(task for name in ('_reading_task', '_ping_interval_task', '_flusher_task',
                                            '_reconnection_task')
                          if isinstance((task := getattr(client, name, None)), asyncio.Task))
            try:
                await client.close()
            except BaseException as error:
                failures.append(error)
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
        for history in self._histories:
            try:
                history.close()
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup('private application resource cleanup', failures)

    def fence(self):
        """End admission synchronously when the owning lifetime ends."""
        self._closed = True
        self._ready = False
        if self._oidc_login is not None:
            self._oidc_login.fence()
        if self._oidc_terminal is not None:
            self._oidc_terminal.fence()
        if self._browser_auth is not None:
            self._browser_auth.close()
        for service in self._services:
            service._closed = True
        if self._storage is not None:
            self._storage.fence()
        if self._policy_service is not None:
            self._policy_service.fence()
        if self._secret_use is not None:
            self._secret_use.fence()
        if self._identity is not None and self._identity._application_lease is not None:
            self._identity._application_lease.done.set()

    async def close(self):
        if asyncio.get_running_loop() is not self._loop:
            raise ApplicationServiceFailure('application_service_owner_loop', self)
        self.fence()
        if (self._closing is None or (self._closing.done() and not self._closing.cancelled()
                and self._closing.exception() is not None)):
            # A pending join is never replaced. A terminal failure can retry
            # cleanup of these same owners; it cannot construct replacements.
            self._closing = asyncio.create_task(self._close())
            self._closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            await asyncio.wait_for(asyncio.shield(self._closing), 15)
        except BaseException as error:
            raise ApplicationServiceFailure('application_service_cleanup_pending', self, error) from None

    async def run(self, *, stop):
        if not isinstance(stop, asyncio.Event):
            raise ContractError('application_service_lifetime_required')
        if stop.is_set():
            await self.close()
            return
        starting = asyncio.create_task(self.start())
        stopping = asyncio.create_task(stop.wait())
        try:
            await asyncio.wait({starting, stopping}, return_when=asyncio.FIRST_COMPLETED)
            if starting.done():
                starting.result()
            while not stop.is_set():
                self.check_health()
                try:
                    await asyncio.wait_for(asyncio.shield(stopping), 1)
                except asyncio.TimeoutError:
                    pass
        finally:
            try:
                await self.close()
            finally:
                if not stopping.done():
                    stopping.cancel()
                await asyncio.gather(starting, stopping, return_exceptions=True)
