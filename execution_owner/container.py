"""One selected task-container adapter; durable business intent remains with D."""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from capability_owner.workspace_host import WorkspaceCheckoutHost
from state_owner.ledger import OwnerLedger, validate_record
from .plans import ExecutionAdmission, ExecutionPlanOwner
from .docker_engine import DockerEngine, fail
from .network import SelectedNetwork
from . import container_programs as programs


class RetainedContainerIntent:
    """Read D's exact existing effect intent, without writing a second journal.

    The retained record has executionBinding/executionPhase in state and the
    fixed container-prepare effect. D owns that record and all later transitions.
    """
    def __init__(self, ledger, binding):
        validate('execution-run-binding', strict_loads(binding))
        value = strict_loads(binding)
        if (not isinstance(ledger, OwnerLedger) or not ledger.completion_budget_required
                or ledger._binding.entity_id != value['runRef']['id']
                or ledger._binding.owner_domain != 'execution'
                or ledger._binding.entity_kind != 'attempt'
                or ledger._binding.hub_id != value['runRef']['ownerHubId']
                or ledger._binding.scope != canonical_bytes(value['scope'])):
            fail('execution_intent_required')
        self._ledger, self.binding = ledger, binding

    async def check(self, *, dispatch=True):
        snapshot = await self._ledger.current()
        if snapshot.latest is None:fail('execution_intent_required')
        latest = validate_record(snapshot.latest.record,self._ledger._binding)
        record = validate_record(snapshot.records[0].record,self._ledger._binding)
        binding = strict_loads(self.binding)
        operation = binding['originalOperation']
        effect = {'effectId': 'container-'+binding['runRef']['id'].removeprefix('execution-'),
            'contractId':'execution-container-prepare', 'payloadDigest':payload_digest(binding),
            'grantRef':operation['grantRef'], 'recovery':'query-before-retry', 'payload':binding}
        if (record['outcome']!='committed' or record['operation']!=operation
                or record['state'].get('executionBinding')!=binding
                or record['state'].get('executionPhase')!='start-intent'
                or latest['state'].get('executionBinding')!=binding
                or latest['state'].get('executionPhase') not in (('start-intent','running') if dispatch else
                    ('start-intent','running','cancel-intent','terminal','unknown'))
                or record.get('authorizationDecision')!={'operationId':operation['operationId'],
                    'decision':'allowed','reason':'authorized','actorRef':operation['effectiveActorRef'],
                    'contractId':'capability-process-start'}
                or effect not in record['effects']):
            fail('execution_intent_required')
        return snapshot.latest

    def __repr__(self):
        return '<RetainedContainerIntent existing owner record>'


@dataclass(frozen=True, slots=True, repr=False)
class ContainerObservation:
    run_ref: bytes
    status: str
    exit_code: int | None = None
    resource_ref: bytes | None = None

    def __repr__(self):
        return '<ContainerObservation '+self.status+'>'


class TaskContainerAdapter:
    def __init__(self, plans, engine, workspace, *, workspace_ref, network):
        if (type(plans) is not ExecutionPlanOwner or type(engine) is not DockerEngine
                or type(workspace) is not WorkspaceCheckoutHost or type(network) is not SelectedNetwork):
            fail('execution_adapter_configuration')
        self._plans,self._engine,self._workspace,self._network=plans,engine,workspace,network
        self._profile=strict_loads(plans._profile)
        if canonical_bytes(workspace_ref)!=canonical_bytes(self._profile['workspaceRef']):
            fail('execution_workspace_selection')
        if any(c in workspace._path for c in ',\x00\r\n'):
            fail('execution_workspace_selection')
        self._network.check(self._profile)
        self._runs,self._jobs={},set()
        self._gate=asyncio.Lock()
        self._closed=False
        self._checkpointed=False

    def __repr__(self):return '<TaskContainerAdapter private>'

    async def _owned(self, method, *args):
        if self._closed:fail('execution_adapter_closed')
        if len(self._jobs)>=16:fail('execution_adapter_busy')
        task=asyncio.create_task(method(*args),name='execution-container-owner')
        self._jobs.add(task)
        def done(original):
            self._jobs.discard(original)
            if not original.cancelled():original.exception()
        task.add_done_callback(done)
        return await asyncio.shield(task)

    async def _fresh(self, admission, inspection, intent):
        if (type(admission) is not ExecutionAdmission or admission._owner is not self._plans
                or type(intent) is not RetainedContainerIntent or intent.binding!=admission.binding):
            fail('execution_intent_required')
        await intent.check()
        if admission.native_binding is not None:
            first=(await intent._ledger.current()).records[0]
            state=strict_loads(first.record)['state']
            if (state.get('nativeBinding')!=strict_loads(admission.native_binding)
                    or admission.valid_until>datetime.fromisoformat(state['admissionEnd'])):
                fail('execution_native_binding_mismatch')
        await self._workspace.check_current()
        source=await asyncio.to_thread(self._workspace.root.read,self._profile['recipe']['path'],
            repository_id=self._workspace._repository['repositoryId'])
        if 'sha256:'+hashlib.sha256(source).hexdigest()!=self._profile['recipe']['sha256']:
            fail('execution_recipe_changed')
        self._workspace.check_files()
        if self._workspace._source._uid!=self._profile['isolation']['workerUID']:
            fail('execution_workspace_selection')
        # Finish all awaited source reads before the final current capability
        # check. That check preserves the original deadline and exact binding.
        return await admission.recheck(inspection)

    def _spec(self, binding, image):
        profile=self._profile
        run=strict_loads(binding)
        end=datetime.fromisoformat(run['executionValidUntil']).timestamp()
        payload={'recipe':profile['recipe'],'end':end}
        command=['/usr/local/bin/python3','-I','-S','-u','-c',programs.BOOT,
            json.dumps(payload,separators=(',',':'))]
        name='amx-task-'+run['runRef']['id'].removeprefix('execution-')[:48]
        labels={'agentmux.task.binding':payload_digest(run), 'agentmux.task.run':run['runRef']['id'],
            'agentmux.task.owner':run['runRef']['ownerHubId'], 'agentmux.task.plan':payload_digest(run['planRef'])}
        uid=profile['isolation']['workerUID']
        tmpfs='rw,noexec,nosuid,nodev,size=1m,mode=0700,uid='+str(uid)+',gid='+str(uid)
        return {'name':name,'command':command,'labels':labels,'image':image['Id'],
            'environment':image.get('Config',{}).get('Env') or [],'uid':uid,'tmpfs':tmpfs,
            'source':self._workspace._path,'end':end}

    def _verify(self, observed, run):
        if type(observed) is not dict:fail('execution_container_identity')
        spec=run['spec'];host=observed.get('HostConfig');config=observed.get('Config')
        mounts=observed.get('Mounts');state=observed.get('State')
        if (type(observed.get('Id')) is not str
                or type(host) is not dict or type(config) is not dict or type(state) is not dict
                or type(host.get('RestartPolicy')) is not dict
                or type(mounts) is not list or any(type(m) is not dict for m in mounts)
                or state.get('Status') not in ('created','running','paused','restarting','removing','exited','dead')
                or type(state.get('Running')) is not bool
                or type(state.get('Pid')) is not int or state['Pid']<0
                or (state['Running'] is False and state['Pid']!=0)):
            fail('execution_container_identity')
        expected_mount={'Type':'bind','Source':spec['source'],'Destination':'/workspace','RW':True}
        binds=[m for m in mounts or [] if m.get('Type')=='bind']
        if (not re.fullmatch('[a-f0-9]{64}',observed.get('Id',''))
                or observed.get('Name')!='/'+spec['name'] or observed.get('Image')!=spec['image']
                or config.get('Labels')!=spec['labels'] or config.get('User')!=str(spec['uid'])+':'+str(spec['uid'])
                or config.get('WorkingDir')!='/workspace' or config.get('Entrypoint')!=spec['command'][:1]
                or config.get('Cmd')!=spec['command'][1:] or config.get('Env',[])!=spec['environment']
                or config.get('Tty') or config.get('OpenStdin')
                or host.get('Privileged') is not False or host.get('ReadonlyRootfs') is not True
                or host.get('NetworkMode')!='none' or host.get('PidMode') not in ('',None)
                or host.get('IpcMode')!='private' or host.get('UTSMode') not in ('',None)
                or host.get('CapAdd') or host.get('CapDrop')!=['ALL']
                or host.get('SecurityOpt')!=['no-new-privileges:true']
                or host.get('Devices') or host.get('DeviceRequests') or host.get('VolumesFrom')
                or host.get('PortBindings') or host.get('PublishAllPorts') or host.get('ExtraHosts')
                or host.get('RestartPolicy',{}).get('Name')!='no'
                or host.get('LogConfig')!={'Type':'none','Config':{}}
                or host.get('Memory')!=self._profile['limits']['memoryBytes']
                or host.get('MemorySwap')!=self._profile['limits']['memoryBytes']
                or host.get('NanoCpus')!=self._profile['limits']['cpuMillis']*1000000
                or host.get('PidsLimit')!=self._profile['limits']['pids']
                or host.get('Tmpfs')!={'/run/agentmux':spec['tmpfs']}
                or len(binds)!=1 or any(binds[0].get(k)!=v for k,v in expected_mount.items())
                or any(m.get('Destination') not in ('/workspace','/run/agentmux') for m in mounts or [])
                or (run.get('id') is not None and observed['Id']!=run['id'])):
            fail('execution_container_identity')
        return observed

    def _observation(self, run, status, exit_code=None):
        binding=strict_loads(run['binding'])
        resource=None
        if run.get('id') is not None:
            resource=canonical_bytes({'format':'agentmux-task-container-v1','runRef':binding['runRef'],
                'bindingDigest':payload_digest(binding),'engineId':self._engine.selection.engine_id,
                'imageId':run['spec']['image'],'containerId':run['id']})
        return ContainerObservation(canonical_bytes(binding['runRef']),status,exit_code,resource)

    async def recover(self, intent, *, resource_ref=None):
        return await self._owned(self._recover,intent,resource_ref)

    async def _recover(self, intent, resource_ref):
        # Recovery observes/stops the exact retained physical resource. It does
        # not grant another task start, network request or private delivery.
        if type(intent) is not RetainedContainerIntent:fail('execution_intent_required')
        await intent.check(dispatch=False)
        binding=strict_loads(intent.binding)
        container_id=None
        if resource_ref is not None:
            resource=strict_loads(resource_ref)
            if type(resource) is not dict:fail('execution_container_identity')
            expected={'format':'agentmux-task-container-v1','runRef':binding['runRef'],
                'bindingDigest':payload_digest(binding),'engineId':self._engine.selection.engine_id,
                'imageId':self._engine.selection.image_id,'containerId':resource.get('containerId')}
            if (resource!=expected or type(resource.get('containerId')) is not str or not re.fullmatch('[a-f0-9]{64}',resource.get('containerId',''))):
                fail('execution_container_identity')
            container_id=resource['containerId']
        async with self._gate:
            if binding['runRef']['id'] in self._runs:
                fail('execution_recovery_already_owned')
            image=await self._engine.check(self._profile)
            run={'binding':intent.binding,'spec':self._spec(intent.binding,image),'id':container_id,
                'intent':intent,'relay':None,'relay_task':None,'unknown':True,'started':False,'recovered':True}
            if container_id is None:
                # A create reply can be lost before D can retain the ID. Observe
                # only; no missing resource or expired admission permits create.
                observed=await self._engine.find(run['spec']['name'])
                if observed is None:return self._observation(run,'unknown')
                self._verify(observed,run)
                run['id']=observed['Id']
            key=binding['runRef']['id']
            if key in self._runs and self._runs[key]['id']!=run['id']:fail('execution_container_identity')
            self._runs[key]=run
            return await self._observe(run)

    async def prepare(self, admission, *, task_inspection, intent):
        return await self._owned(self._prepare,admission,task_inspection,intent)

    async def _prepare(self, admission, inspection, intent):
        async with self._gate:
            admission=await self._fresh(admission,inspection,intent)
            binding=admission.binding
            key=strict_loads(binding)['runRef']['id']
            run=self._runs.get(key)
            if run is not None:
                if run['binding']!=binding:fail('execution_original_conflict')
                if run.get('removed'):fail('execution_container_removed')
                # No implicit repeated engine mutation after uncertainty.
                return await self._observe(run)
            image=await self._engine.check(self._profile)
            admission=await self._fresh(admission,inspection,intent)
            spec=self._spec(binding,image)
            run={'binding':binding,'spec':spec,'id':None,'admission':admission,'intent':intent,
                'inspection':inspection,'relay':None,'relay_task':None,'unknown':False,'started':False}
            self._runs[key]=run
            try:
                existing=await self._engine.find(spec['name'])
                if existing is None:
                    await self._fresh(admission,inspection,intent)
                    limits=self._profile['limits']
                    args=['create','--name',spec['name'],'--pull','never','--platform','linux/arm64',
                        '--network','none','--ipc','private','--read-only','--cap-drop','ALL',
                        '--security-opt','no-new-privileges:true','--user',str(spec['uid'])+':'+str(spec['uid']),
                        '--workdir','/workspace','--memory',str(limits['memoryBytes']),
                        '--memory-swap',str(limits['memoryBytes']),'--cpus',str(limits['cpuMillis']/1000),
                        '--pids-limit',str(limits['pids']),'--restart','no','--log-driver','none',
                        '--mount','type=bind,src='+spec['source']+',dst=/workspace',
                        '--tmpfs','/run/agentmux:'+spec['tmpfs'],'--entrypoint',spec['command'][0]]
                    for name,value in spec['labels'].items():args.extend(('--label',name+'='+value))
                    args.extend((self._profile['image'],*spec['command'][1:]))
                    result=await self._engine._run(args)
                    cid=result.decode('ascii').strip()
                    if not re.fullmatch('[a-f0-9]{64}',cid):fail('execution_engine_observation_invalid')
                    run['id']=cid
                    existing=await self._engine.inspect(cid)
                self._verify(existing,run);run['id']=existing['Id']
                # A recovered running/terminal container is observed, never
                # automatically restarted or supplied another relay/credential.
                if existing['State']['Status']!='created':
                    run['recovered']=True
                    run['unknown']=True
                    return await self._observe(run)
                await self._fresh(admission,inspection,intent)
                await self._engine._run(('start',run['id']))
                self._verify(await self._engine.inspect(run['id']),run)
                await self._engine.exec_fixed(run['id'],spec['uid'],programs.READY)
                if self._profile['network']['mode']=='scoped-egress':
                    run['relay']=await self._engine.relay(run['id'],spec['uid'],programs.RELAY)
                    run['relay_task']=asyncio.create_task(self._relay(run),name='execution-private-network')
                    await self._engine.exec_fixed(run['id'],spec['uid'],programs.NETWORK_READY)
                return self._observation(run,'prepared')
            except BaseException:
                run['unknown']=True
                raise

    async def _relay(self, run):
        process=run['relay']
        try:
            for _ in range(128):
                raw=bytearray()
                while not raw.endswith(b'\n') and len(raw)<=8192:
                    byte=await process.stdout.read(1)
                    if not byte:return
                    raw.extend(byte)
                if len(raw)>8192:return
                response={'status':'denied'}
                try:
                    await self._fresh(run['admission'],run['inspection'],run['intent'])
                    response=await self._network.read(strict_loads(bytes(raw)))
                    await self._fresh(run['admission'],run['inspection'],run['intent'])
                except Exception:response={'status':'denied'}
                process.stdin.write(canonical_bytes(response)+b'\n')
                await process.stdin.drain()
        except (Exception,asyncio.CancelledError):
            pass
        finally:
            if process.returncode is None:process.kill()
            # Keep this same original reader through EOF, even after excess or
            # malformed task traffic; do not wait behind a paused full pipe.
            while await process.stdout.read(8192):pass
            await process.wait()

    def _run(self, reference):
        validate('execution-plan-read',{'planRef':reference})
        run=self._runs.get(reference['id'])
        if run is None or strict_loads(run['binding'])['runRef']!=reference:
            fail('execution_container_unknown')
        return run

    async def start(self, run_ref, admission, *, task_inspection, intent):
        return await self._owned(self._start,run_ref,admission,task_inspection,intent)

    async def _start(self, reference, admission, inspection, intent):
        async with self._gate:
            run=self._run(reference)
            if run['unknown'] or run.get('removed'):fail('execution_container_unknown')
            if admission.binding!=run['binding']:fail('execution_original_conflict')
            run['admission']=await self._fresh(admission,inspection,intent)
            run['inspection']=inspection
            await self._engine.check_transport()
            self._verify(await self._engine.inspect(run['id']),run)
            run['admission']=await self._fresh(admission,inspection,intent)
            if not run['started']:
                # Mark before the command: a lost response never repeats start.
                run['started']=True
                try:await self._engine.exec_fixed(run['id'],run['spec']['uid'],programs.START)
                except BaseException:
                    run['unknown']=True
                    raise
            return await self._observe(run)

    async def observe(self, run_ref):return await self._owned(self._observe,self._run(run_ref))

    async def _observe(self, run):
        reference=canonical_bytes(strict_loads(run['binding'])['runRef'])
        if run.get('removed'):return self._observation(run,'terminal')
        try:
            observed=await self._engine.find(run['spec']['name'])
            if observed is None:return self._observation(run,'unknown')
            self._verify(observed,run);run['id']=observed['Id']
            state=observed.get('State',{})
            if state.get('Status') in ('exited','dead') and state.get('Running') is False:
                code=state.get('ExitCode')
                if type(code) is not int or not 0<=code<=255:fail('execution_engine_observation_invalid')
                return self._observation(run,'terminal',code)
            if state.get('Status')=='running' and state.get('Running') is True:
                return self._observation(run,'pending' if run.get('recovered') or run['unknown'] else ('running' if run['started'] else 'prepared'))
            if state.get('Status')=='created':return self._observation(run,'pending')
            return self._observation(run,'pending')
        except ContractError:return self._observation(run,'unknown')

    async def deliver_private(self, run_ref, admission, *, task_inspection, intent, worker_ref, consumer_ref, material):
        # Called only by C's owner-native selected consumer after its own custody
        # and current credential checks. No public service exposes this method.
        return await self._owned(self._deliver,run_ref,admission,task_inspection,intent,worker_ref,consumer_ref,material)

    async def _deliver(self, reference, admission, inspection, intent, worker, consumer, material):
        async with self._gate:
            run=self._run(reference)
            if (admission.binding!=run['binding'] or worker!=self._profile['workerIdentityRef']
                    or consumer!=self._profile['consumerRef'] or type(material) is not bytes
                    or not 0<len(material)<=16384 or run['started'] or run['unknown'] or run.get('private_attempted')):
                fail('execution_private_channel_refused')
            await self._fresh(admission,inspection,intent)
            await self._engine.check_transport()
            self._verify(await self._engine.inspect(run['id']),run)
            await self._fresh(admission,inspection,intent)
            run['private_attempted']=True
            try:
                await self._engine.exec_fixed(run['id'],run['spec']['uid'],programs.DELIVER,data=material)
            except BaseException:
                run['unknown']=True
                raise
            return self._observation(run,'prepared')

    async def stop(self, run_ref):return await self._owned(self._stop,self._run(run_ref))

    async def _stop(self, run):
        async with self._gate:
            await self._engine.check_transport()
            observed=await self._engine.find(run['spec']['name'])
            if observed is None:return self._observation(run,'unknown')
            self._verify(observed,run);run['id']=observed['Id']
            try:await self._engine._run(('stop','--time','1',run['id']))
            except ContractError:run['unknown']=True
            result=await self._observe(run)
            if result.status=='terminal':await self._join_relay(run)
            return result

    async def _join_relay(self, run):
        process=run['relay']
        if process is not None and process.returncode is None:process.kill()
        if run['relay_task'] is not None:await run['relay_task']
        if process is not None:await process.wait()

    async def cleanup(self, run_ref):return await self._owned(self._cleanup,self._run(run_ref))

    async def _cleanup(self, run):
        async with self._gate:
            await self._engine.check_transport()
            observed=await self._engine.find(run['spec']['name'])
            if observed is None:
                # Absence alone is not proof this adapter joined its original.
                if not run.get('removed'):fail('execution_cleanup_unknown')
                return
            self._verify(observed,run)
            if observed.get('State',{}).get('Running') is not False:
                fail('execution_cleanup_running')
            if observed.get('State',{}).get('Status') not in ('created','exited','dead'):
                fail('execution_cleanup_unknown')
            await self._join_relay(run)
            await self._engine._run(('rm',observed['Id']))
            if await self._engine.find(run['spec']['name']) is not None:fail('execution_cleanup_unknown')
            run['removed']=True

    async def checkpoint(self, *, timeout=10):
        """Join host clients and retain exact live resources for D's recovery.

        This stops admission/network relay, not the task. The returned pending
        observations never authorize releasing a reservation or its custody.
        """
        self._closed=True
        if self._jobs:
            _,pending=await asyncio.wait(tuple(self._jobs),timeout=timeout)
            if pending:fail('execution_cleanup_unknown')
        result=[]
        for run in self._runs.values():
            await self._join_relay(run)
            result.append(self._observation(run,'pending'))
        self._checkpointed=True
        return tuple(result)

    async def close(self, *, timeout=10):
        self._closed=True
        if self._jobs:
            _,pending=await asyncio.wait(tuple(self._jobs),timeout=timeout)
            if pending:fail('execution_cleanup_unknown')
        if self._checkpointed:
            return
        for run in self._runs.values():
            if not run.get('removed'):
                result=await self._stop(run)
                if result.status not in ('terminal','pending'):fail('execution_cleanup_unknown')
                await self._cleanup(run)
