"""Selected Process receivers, fixed owner composition and joined shutdown."""
import asyncio
import base64
from datetime import datetime
import ssl

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.session import FederationSession
from hub.nats_transport import new_client
from identity.ingress import EnrolledIngress
from identity.process_selection import (check_process_authority, ledger_binding, load_connection,
    load_receiver_seed, load_signer, retention)
from native_security.secret_custody import ScopedSecretCustody
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, StreamIdentity, owner_subject
from state_owner.task_service import TaskService
from execution_owner.plans import ExecutionPlanOwner
from execution_owner.container import TaskContainerAdapter
from execution_owner.docker_engine import DockerEngine, DockerSelection
from execution_owner.network import SelectedNetwork, HTTPSDestination
from execution_owner.task_credentials import TaskCredentialOwner, TaskCredentialPolicy
from execution_owner.retained import ExecutionServiceSigner
from .process_admission import ProcessRunAdmission
from .process_resource import ProcessResource, ProcessInspectionSigner
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageFailure


class ProcessHost:
    def __init__(self,selection,*,identity,task,workspace):
        from identity.application_service_selection import ApplicationServiceSelection
        from state_owner.task_host import TaskHost
        from .workspace_host import WorkspaceReadHost
        if (type(selection) is not ApplicationServiceSelection or selection.policy.get('process') is None
                or type(task) is not TaskHost or type(workspace) is not WorkspaceReadHost
                or workspace._task is not task):raise ContractError('capability_process_configuration')
        self._selection,self._identity,self._task,self._workspace=selection,identity,task,workspace
        self._authority,self._ingress=selection.check_storage_identity_source(identity)
        if task.owner._authority is not self._authority:raise ContractError('capability_process_configuration')
        self._loop=asyncio.get_running_loop();self._closed=self._ready=False
        self._starting=self._closing=self._resource=self._admission=self._plans=self._credentials=self._adapter=None
        self._consumer=None;self._clients=[];self._sessions=[];self._connects=[];self._receivers=[];self._histories=[];self._files=set()

    def __repr__(self):return '<ProcessHost private>'

    def _open(self):
        if self._closed or asyncio.get_running_loop() is not self._loop:raise ContractError('capability_process_stale')
        self._task.check_health();self._workspace.check_health()
        if self._selection.check_storage_identity_source(self._identity)[0] is not self._authority:raise ContractError('capability_process_stale')

    async def _file(self,function,*args):
        original=asyncio.create_task(asyncio.to_thread(function,*args));self._files.add(original)
        try:
            await asyncio.wait({original});return original.result()
        finally:
            if original.done():self._files.discard(original)

    async def _lost(self,*_args):self.fence()

    async def _connect(self,name):
        value=self._selection.policy;pin=value['process']
        entry=pin['state'] if name=='state' else pin['receivers'][name]
        connection=entry['connection']
        await self._file(load_connection,value,name)
        client=new_client(require_tls=True,leaf_certificate_sha256=connection['leafCertificateSHA256'])
        self._clients.append(client);session=FederationSession();self._sessions.append(session);client._agentmux_session=session
        def signature(nonce):
            key=nkeys.from_seed(load_connection(value,name).seed)
            try:return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:key.wipe()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=connection['rootsPEM'])
        original=asyncio.create_task(client.connect(servers=[connection['endpoint']],tls=context,
            tls_hostname=connection['serverName'],tls_handshake_first=True,
            user_jwt_cb=lambda:load_connection(value,name).jwt.encode('ascii'),signature_cb=signature,
            inbox_prefix=entry['credentials']['replyPrefix'],name='agentmux-process-'+name,
            allow_reconnect=False,max_reconnect_attempts=0,connect_timeout=3,dont_randomize=True,no_echo=True,
            disconnected_cb=self._lost,reconnected_cb=self._lost,closed_cb=self._lost,error_cb=self._lost))
        self._connects.append(original);await asyncio.wait({original});original.result();self._open()
        if client.is_connected is not True:raise ContractError('capability_process_stale')
        return client

    def _ledger(self,js,pin,domain,kind):
        binding=ledger_binding(self._selection.policy,pin,domain,kind)
        source=StreamIdentity(datetime.fromisoformat(pin['streamIdentity']['created']),pin['streamIdentity']['minimumSequence'])
        history=OwnerHistory(pin['history']['path'],binding,stream_identity=source,
            max_records=pin['history']['maxRecords'],max_bytes=pin['history']['maxBytes'])
        self._histories.append(history)
        return OwnerLedger(js,stream=pin['stream'],subject=owner_subject(binding),binding=binding,
            retention=retention(pin['retention']),stream_identity=source,history=history,require_completion_budget=True)

    async def _start(self):
        self._open();await check_process_authority(self._selection,self._identity)
        value=self._selection.policy;pin=value['process'];signer=pin['signer'];profile=pin['profile']
        state=await self._connect('state');js=state.jetstream()
        plans=self._ledger(js,pin['plans'],'execution-plans','approved-execution-plan')
        credentials=self._ledger(js,pin['credentialsLedger'],'task-credentials','effect')
        await plans.current();await credentials.current()
        self._plans=ExecutionPlanOwner(self._authority,plans,self._task.owner,self._ingress,
            executor_ref=pin['executorRef'],enrollment_identity_ref=pin['enrollmentIdentityRef'],profile=profile)
        engine=DockerEngine(DockerSelection(**pin['docker']))
        destinations=[HTTPSDestination(canonical_bytes(item['reference']),item['host'],item['address'],
            item['port'],item['path'],item['rootsPEM']) for item in pin['networkDestinations']]
        self._adapter=TaskContainerAdapter(self._plans,engine,self._workspace._checkout,
            workspace_ref=profile['workspaceRef'],network=SelectedNetwork(profile['network']['profileRef'],destinations))
        service_ingress=EnrolledIngress(self._authority,issuer_ref=strict_loads(self._ingress._issuer_ref),signing_seed=self._ingress._seed)
        source=self._task.service;task_pin=value['task'];destination=task_pin['connection']
        # Use the exact selected task owner, source and signer. The human gate
        # remains on public ingress; this private worker route accepts enrolled
        # service authority and retains the actual TaskHost health fence.
        self._consumer=TaskService(self._task.owner,service_ingress,connection=None,
            service_identity_ref=strict_loads(source._identity),service_instance_id=source._instance,
            signing_key_ref=strict_loads(source._issuer),signing_seed=source._seed,
            requester_reply_prefix=task_pin['requesterReplyPrefix'],account_public_key=task_pin['credentials']['accountPublicKey'])
        self._consumer._host=self._task
        account=signer['accountPayload']
        policy=TaskCredentialPolicy(canonical_bytes(profile['consumerRef']),destination['endpoint'],destination['serverName'],
            destination['rootsPEM'].encode('ascii'),destination['leafCertificateSHA256'],canonical_bytes(account['accountRef']),
            account['accountPublicKey'],self._ingress._issuer_ref,task_pin['requesterReplyPrefix'])
        self._credentials=TaskCredentialOwner(self._authority,credentials,ScopedSecretCustody(pin['accountCustodyRoot'],self._authority),
            self._adapter,self._consumer,policy=policy,custody_root=pin['custodyRoot'],owner_identity_ref=signer['ownerIdentityRef'])
        seed=await self._file(load_signer,signer)
        owner_signer=ExecutionServiceSigner(service_ingress,owner_identity_ref=signer['ownerIdentityRef'],
            transport_ref=signer['transportRef'],grants=signer['grants'],signing_seed=seed,account_payload=account,
            task_read_grant_ref=signer['taskReadGrantRef'],task_approval_refs=signer['taskApprovalRefs'])
        run=pin['run']
        self._admission=ProcessRunAdmission(self._plans,self._adapter,self._credentials,owner_signer,
            jetstream=js,stream=run['stream'],retention=retention(run['retention']),
            inventory_root=run['inventoryRoot'],namespace=run['namespace'])
        self._admission._host=self
        inspection=ProcessInspectionSigner(service_ingress,transport_ref=signer['transportRef'],grant_ref=signer['inspectionGrantRef'],signing_seed=seed)
        self._resource=ProcessResource(self._admission,inspection,plugin_identity=pin['pluginIdentityRef'],
            instance_id=pin['instanceId'],package_id=pin['packageId'],terminal_owner=self._identity)
        for name,receiver in pin['receivers'].items():
            signing_seed=await self._file(load_receiver_seed,value,name);connection=await self._connect(name)
            service=CapabilityReplyService(self._authority,resources=(self._resource,),
                hub_id=value['kernelScope']['hubId'],profile_id=value['kernelScope']['profileId'],authority_id=value['authorityId'],
                service_id=name+'-owner',service_identity_ref=receiver['serviceIdentityRef'],service_instance_id=receiver['serviceInstanceId'],
                signing_key_ref=receiver['issuer']['issuerRef'],signing_seed=signing_seed,
                request_signing_key_ref=receiver['requestSigningKeyRef'],connection=connection)
            self._receivers.append(service);await service.start()
        await check_process_authority(self._selection,self._identity);self._open();self._ready=True;self.check_health()

    async def start(self):
        self._open()
        if self._starting is not None:raise ContractError('capability_process_stale')
        self._starting=asyncio.create_task(self._start())
        self._starting.add_done_callback(lambda t:None if t.cancelled() else t.exception())
        try:await asyncio.wait({self._starting});self._starting.result()
        except asyncio.CancelledError:self.fence();raise
        except Exception as error:
            self.fence();raise SelectedStorageFailure('capability_process_start_unconfirmed',self,error) from None

    def check_health(self):
        self._open()
        if not self._ready or len(self._receivers)!=2 or any(s._closed or s._subscription is None for s in self._receivers):raise ContractError('capability_process_stale')
        self._resource._current()

    async def enrollment(self):
        """Native administrator handoff; never applies identity enrollment."""
        self.check_health();owner=await self._admission.existing()
        if owner is None:raise ContractError('execution_not_found')
        snapshot,state=await owner._load()
        return await owner.enrollment(await self._admission._signer.observe(state['executionBinding'],snapshot.sequence))

    def fence(self):
        self._closed=True;self._ready=False
        for service in self._receivers:service._closed=True

    async def _cleanup(self):
        if self._starting is not None:await asyncio.gather(self._starting,return_exceptions=True)
        for service in self._receivers:
            try:await service.close(timeout=10)
            except ContractError:
                if service._cleanup_task is None:raise
                await asyncio.shield(service._cleanup_task)
        if self._resource is not None:await self._resource.close()
        elif self._admission is not None:await self._admission.close()
        else:
            if self._credentials is not None:await self._credentials.close()
            if self._adapter is not None:await self._adapter.checkpoint()
        if self._consumer is not None:await self._consumer.close(timeout=None)
        if self._plans is not None:await self._plans.close()
        for history in self._histories:history.close()
        if self._files:await asyncio.gather(*tuple(self._files),return_exceptions=True)
        for original in self._connects:await asyncio.gather(original,return_exceptions=True)
        for session in self._sessions:await session.close()
        for client in self._clients:await client.close()

    async def close(self,*,timeout=5):
        if timeout is not None and (type(timeout) not in (int,float) or not 0<timeout<=10):raise ContractError('capability_cleanup_invalid')
        self.fence()
        if self._closing is None or self._closing.done() and (self._closing.cancelled() or self._closing.exception() is not None):
            self._closing=asyncio.create_task(self._cleanup());self._closing.add_done_callback(lambda t:None if t.cancelled() else t.exception())
        try:
            done,_=await asyncio.wait({self._closing},timeout=timeout)
            if not done:raise TimeoutError
            self._closing.result()
        except asyncio.CancelledError:raise
        except Exception as error:raise SelectedStorageFailure('capability_cleanup_incomplete',self,error) from None
