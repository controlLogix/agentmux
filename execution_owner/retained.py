"""Retain one approved task execution across observer and host loss.

The native host selects every owner and key. Public capability requests can name
only the approved executor/plan or its original run. No uncertain effect retries.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import secrets
import uuid

from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                               sign_claims, strict_loads, validate)
from identity.authority import LedgerAuthorityReader, evaluate_snapshot
from identity.ingress import EnrolledIngress
from state_owner.ledger import OwnerLedger, validate_record
from .plans import ExecutionPlanOwner, ExecutionAdmission
from .container import TaskContainerAdapter, RetainedContainerIntent
from .task_credentials import TaskCredentialOwner


def fail(code='execution_owner_refused'):
    raise ContractError(code) from None


def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00','Z')


CREDENTIAL_COMMANDS=frozenset('task-credential-'+name for name in ('prepare','deliver','observe','retire'))
SERVICE_COMMANDS=CREDENTIAL_COMMANDS | {'identity-application-account-resolve','execution-run-record','execution-run-observe'}
STEPS=('credential-prepare-intent','pending-enrollment','container-create-intent','container-prepared',
       'delivery-intent','credential-delivered','proof-intent','proved','start-effect-intent','running',
       'cancel-intent','terminal','retired','unknown')


class ExecutionServiceSigner:
    """A finite native signer using a separately enrolled service and grants."""
    def __init__(self, ingress, *, owner_identity_ref, transport_ref, grants,
                 signing_seed, account_payload, task_read_grant_ref, task_approval_refs):
        if (type(ingress) is not EnrolledIngress or ingress._session_authorizer is not None
                or type(signing_seed) is not bytes or len(signing_seed)!=32
                or type(grants) is not dict or set(grants)!=SERVICE_COMMANDS):
            fail('execution_signer_configuration')
        for reference in (owner_identity_ref,transport_ref,task_read_grant_ref,*grants.values(),*task_approval_refs):
            validate('execution-plan-read',{'planRef':reference})
            if reference['ownerHubId']!=ingress._reader._hub:fail('execution_signer_configuration')
        validate('identity-application-account-resolve',account_payload)
        self._ingress=ingress;self._owner=canonical_bytes(owner_identity_ref)
        self._transport=canonical_bytes(transport_ref);self._grants=canonical_bytes(grants)
        self._seed=signing_seed;self._account=canonical_bytes(account_payload)
        self._read=canonical_bytes(task_read_grant_ref);self._approvals=canonical_bytes(task_approval_refs)

    def __repr__(self):return '<ExecutionServiceSigner private>'

    async def _admit(self,contract,payload,sequence,cancellation_ref):
        if contract not in SERVICE_COMMANDS:fail()
        validate(contract,payload)
        reader=self._ingress._reader;now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','hubId':reader._hub,'profileId':reader._profile,
            'authorityId':reader._entity,'transportRef':strict_loads(self._transport),
            'grantRef':strict_loads(self._grants)[contract],
            'operationId':'execution-service-'+secrets.token_hex(20),'expectedVersion':sequence,
            'contractId':contract,'payload':payload,'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        request=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,self._seed)})
        admitted=await self._ingress.admit(request,cancellation_ref=cancellation_ref)
        if admitted.decision.outcome!='allowed' or admitted.envelope is None:fail('execution_service_not_authorized')
        operation=strict_loads(admitted.envelope)['operation']
        if (canonical_bytes(operation['effectiveActorRef'])!=self._owner
                or operation['caller']['kind']!='service'):fail('execution_service_not_authorized')
        return admitted.envelope

    async def credential(self,phase,run,sequence,cancellation_ref):
        contract='task-credential-'+phase
        if contract not in CREDENTIAL_COMMANDS:fail()
        payload={'credentialRef':run['credentialRef'],'runRef':run['runRef']}
        if phase=='prepare':payload.update(taskReadGrantRef=strict_loads(self._read),taskApprovalRefs=strict_loads(self._approvals))
        return await self._admit(contract,payload,sequence,cancellation_ref)

    async def account(self,cancellation_ref):
        return await self._admit('identity-application-account-resolve',strict_loads(self._account),0,cancellation_ref)

    async def record(self,state,sequence):
        return await self._admit('execution-run-record',{'runRef':state['executionBinding']['runRef'],
            'stateDigest':payload_digest(state)},sequence,state['executionBinding']['originalOperation']['cancellationRef'])

    async def observe(self,run,sequence):
        return await self._admit('execution-run-observe',{'runRef':run['runRef']},sequence,
            run['originalOperation']['cancellationRef'])


class RetainedExecutionOwner:
    """One host-selected execution ledger. Construction grants no permission."""
    def __init__(self, authority, ledger, plans, adapter, credentials, signer):
        if (type(authority) is not LedgerAuthorityReader or not isinstance(ledger,OwnerLedger)
                or type(plans) is not ExecutionPlanOwner or plans._authority is not authority
                or type(adapter) is not TaskContainerAdapter or adapter._plans is not plans
                or type(credentials) is not TaskCredentialOwner or credentials._adapter is not adapter
                or type(signer) is not ExecutionServiceSigner or signer._ingress._reader is not authority
                or credentials._owner!=signer._owner or not ledger.completion_budget_required
                or (ledger._binding.owner_domain,ledger._binding.entity_kind)!=('execution','attempt')
                or ledger._binding.scope!=plans._ledger._binding.scope or ledger._binding.hub_id!=authority._hub):
            fail('execution_owner_configuration')
        self._authority,self._ledger,self._plans=authority,ledger,plans
        self._adapter,self._credentials,self._signer=adapter,credentials,signer
        self._gate=asyncio.Lock();self._dispatch=asyncio.Lock();self._jobs=set()
        self._closed=False;self._closing=None

    def __repr__(self):return '<RetainedExecutionOwner private>'

    async def _owned(self,method,*args):
        if self._closed or len(self._jobs)>=16:fail('execution_owner_unavailable')
        task=asyncio.create_task(method(*args),name='retained-execution-owner');self._jobs.add(task)
        def done(original):
            self._jobs.discard(original)
            if not original.cancelled():original.exception()
        task.add_done_callback(done)
        return await asyncio.shield(task)

    def _history(self,snapshot):
        first=None;previous=None
        for item in snapshot.records:
            record=validate_record(item.record,self._ledger._binding);state=record['state']
            validate('retained-execution-state',state)
            binding=state['executionBinding'];original=state['originalEnvelope']
            if (binding['runRef']['id']!=self._ledger._binding.entity_id
                    or binding['executorRef']!=strict_loads(self._plans._executor)
                    or canonical_bytes(binding['scope'])!=self._ledger._binding.scope
                    or original['operation']!=binding['originalOperation']
                    or original['contractId']!='capability-process-start'
                    or original['payload']!={'resourceRef':binding['executorRef'],'input':{'planRef':binding['planRef']}}
                    or record['outcome']!='committed' or record['artifacts'] or record['repository'] is not None):
                fail('execution_history_invalid')
            if (state['resourceRef'] is not None and (state['resourceRef']['runRef']!=binding['runRef']
                    or state['resourceRef']['bindingDigest']!=payload_digest(binding))):fail('execution_history_invalid')
            if state['credentialPrepare']['contractId']!='task-credential-prepare' or state['credentialPrepare']['payload']['runRef']!=binding['runRef']:
                fail('execution_history_invalid')
            if datetime.fromisoformat(state['admissionEnd'])>datetime.fromisoformat(binding['executionValidUntil']):fail('execution_history_invalid')
            native=state.get('nativeBinding')
            if native is not None:
                from identity.execution_evidence import business
                if (native['firstEnvelopeDigest']!=payload_digest(original)
                        or native['businessDigest']!=payload_digest(business(original))
                        or native['businessEnd']!=state['admissionEnd']):fail('execution_history_invalid')
            decision={'operationId':record['operation']['operationId'],'decision':'allowed','reason':'authorized',
                'actorRef':record['operation']['effectiveActorRef'],'contractId':original['contractId'] if first is None else
                record.get('authorizationDecision',{}).get('contractId')}
            if record.get('authorizationDecision')!=decision:fail('execution_history_invalid')
            if first is None:
                if (record['operation']!=binding['originalOperation'] or state['executionPhase']!='start-intent'
                        or state['step']!='credential-prepare-intent'):fail('execution_history_invalid')
                effect={'effectId':'container-'+binding['runRef']['id'].removeprefix('execution-'),
                    'contractId':'execution-container-prepare','payloadDigest':payload_digest(binding),
                    'grantRef':binding['originalOperation']['grantRef'],'recovery':'query-before-retry','payload':binding}
                if record['effects']!=[effect]:fail('execution_history_invalid')
                first=state
            else:
                if (state.get('nativeBinding')!=first.get('nativeBinding') or any(state[key]!=first[key] for key in ('executionBinding','originalEnvelope','admissionEnd','credentialPrepare'))):
                    fail('execution_history_invalid')
                if record['effects']:fail('execution_history_invalid')
                contract=decision['contractId'];op=record['operation']
                if contract=='execution-run-record':
                    if (canonical_bytes(op['effectiveActorRef'])!=self._signer._owner or op['caller']['kind']!='service'
                            or op['expectedVersion']!=item.sequence-1
                            or op['payloadDigest']!=payload_digest({'runRef':binding['runRef'],'stateDigest':payload_digest(state)})):
                        fail('execution_history_invalid')
                elif contract=='capability-process-cancel':
                    if (op['payloadDigest']!=payload_digest({'resourceRef':binding['executorRef'],'input':{'runRef':binding['runRef']}})
                            or state['executionPhase']!='cancel-intent'):fail('execution_history_invalid')
                else:fail('execution_history_invalid')
                if previous['executionPhase'] in ('cancel-intent','terminal') and state['executionPhase'] not in ('cancel-intent','terminal','unknown'):
                    fail('execution_history_invalid')
            previous=state
        return previous

    async def _load(self):
        snapshot=await self._ledger.current()
        return snapshot,self._history(snapshot)

    async def _authorize(self,raw,contract,*,service=False):
        env=strict_loads(raw);validate('message-envelope',env)
        if canonical_bytes(env)!=raw or env['contractId']!=contract:fail()
        validate(contract,env['payload']);op=env['operation']
        if canonical_bytes(op['scope'])!=self._ledger._binding.scope:fail('execution_scope_mismatch')
        if service and (op['caller']['kind']!='service' or canonical_bytes(op['effectiveActorRef'])!=self._signer._owner):
            fail('execution_service_not_authorized')
        async def current():
            decision=evaluate_snapshot(await self._authority.current(),raw,
                audience={'hubId':self._authority._hub,'serviceId':'process-owner'},now=datetime.now(timezone.utc))
            if (decision.outcome!='allowed' or decision.operation!=canonical_bytes(op)
                    or decision.valid_until is None or datetime.now(timezone.utc)>=decision.valid_until):fail('execution_not_authorized')
            return decision.valid_until
        end=await current()
        if op['caller']['kind']=='human':
            await self._plans._ingress.authorize_terminal(op);end=min(end,await current())
        return env,end

    async def _append(self,env,state,snapshot,end,*,first=False):
        validate('retained-execution-state',state)
        b=self._ledger._binding;op=env['operation'];sequence=snapshot.sequence+1
        if sequence>14:fail('execution_completion_bound')
        record={'schemaVersion':'1.0.0','recordId':'execution-record-'+uuid.uuid4().hex,
            'entityId':b.entity_id,'entityKind':b.entity_kind,'ownerHubId':b.hub_id,'ownerDomain':b.owner_domain,
            'entityVersion':sequence,'previousRevision':snapshot.sequence,'operation':op,'recordedAt':stamp(datetime.now(timezone.utc)),
            'outcome':'committed','state':state,'effects':[],'artifacts':[],'repository':None,
            'authorizationDecision':{'operationId':op['operationId'],'decision':'allowed','reason':'authorized',
                'actorRef':op['effectiveActorRef'],'contractId':env['contractId']}}
        if first:
            binding=state['executionBinding']
            record['effects']=[{'effectId':'container-'+binding['runRef']['id'].removeprefix('execution-'),
                'contractId':'execution-container-prepare','payloadDigest':payload_digest(binding),
                'grantRef':op['grantRef'],'recovery':'query-before-retry','payload':binding}]
        await self._ledger.append(record,expected_sequence=snapshot.sequence,valid_until=end,
            expected_target_version=op['expectedVersion'] if env['contractId'] in ('capability-process-start','capability-process-cancel') else None,
            admission='bulk' if first else 'completion',completion_records=14-sequence)
        return state

    async def _save(self,step,*,phase=None,resource=None,enrollment=None):
        async with self._gate:
            snapshot,state=await self._load()
            if state is None:fail()
            if state['executionPhase'] in ('cancel-intent','terminal') and phase not in ('cancel-intent','terminal','unknown'):
                fail('execution_cancel_retained')
            next_state={**state,'step':step,'executionPhase':phase or state['executionPhase']}
            if resource is not None:next_state['resourceRef']=strict_loads(resource)
            if enrollment is not None:next_state['enrollment']=enrollment
            if next_state==state:return state
            raw=await self._signer.record(next_state,snapshot.sequence)
            env,end=await self._authorize(raw,'execution-run-record',service=True)
            return await self._append(env,next_state,snapshot,end)

    def _view(self,state):
        return canonical_bytes({'runRef':state['executionBinding']['runRef'],
            'status':state['executionPhase'],'step':state['step']})

    def _admission(self,state,evidence=None):
        native=state.get('nativeBinding')
        if (native is None)!=(evidence is None):fail('execution_native_evidence_required')
        return ExecutionAdmission(self._plans,canonical_bytes(state['originalEnvelope']),
            canonical_bytes(state['executionBinding']),datetime.fromisoformat(state['admissionEnd']),
            evidence,None if native is None else canonical_bytes(native))

    async def _native_disclosure(self,state,evidence):
        if evidence is not None:
            await evidence.authorize(self._authority,canonical_bytes(state['originalEnvelope']),
                retained=canonical_bytes(state['nativeBinding']))

    @staticmethod
    def _native_ingress(evidence):
        if evidence is not None:
            from identity.execution_evidence import NativeExecutionEvidence
            if type(evidence) is not NativeExecutionEvidence:fail('execution_native_evidence_required')

    async def start(self,raw,*,task_inspection,native_evidence=None):
        self._native_ingress(native_evidence)
        return await self._owned(self._start,raw,task_inspection,native_evidence)

    async def _start(self,raw,inspection,native_evidence):
        async with self._dispatch:
            async with self._gate:
                snapshot,state=await self._load()
                if state is not None:
                    if strict_loads(raw)!=state['originalEnvelope']:fail('execution_original_conflict')
                    await self._admission(state,native_evidence).recheck(inspection)
                    await self._native_disclosure(state,native_evidence)
                    return self._view(state)
                admission=await self._plans.admit_start(raw,task_inspection=inspection,native_evidence=native_evidence)
                binding=strict_loads(admission.binding)
                if binding['runRef']['id']!=self._ledger._binding.entity_id:fail('execution_run_selection')
                cancellation=binding['originalOperation']['cancellationRef']
                prepare=await self._signer.credential('prepare',binding,0,cancellation)
                state={'executionBinding':binding,'originalEnvelope':strict_loads(raw),'admissionEnd':stamp(admission.valid_until),
                    'executionPhase':'start-intent','step':'credential-prepare-intent','credentialPrepare':strict_loads(prepare),
                    'resourceRef':None,'enrollment':None}
                if admission.native_binding is not None:state['nativeBinding']=strict_loads(admission.native_binding)
                admission=await admission.recheck(inspection)
                await self._append(strict_loads(raw),state,snapshot,admission.valid_until,first=True)
            # The saved command identifies the first immutable C generation. A
            # lost reply is reconciled; it is never replaced by another command.
            result=strict_loads(await self._credentials.prepare(prepare,admission,task_inspection=inspection,
                account_request=await self._signer.account(cancellation)))
            state=await self._save('pending-enrollment',enrollment=result)
            await admission.recheck(inspection)
            await self._native_disclosure(state,native_evidence)
            return self._view(state)

    async def enrollment(self,raw):
        """Native administrator handoff only; this never applies identity enrollment."""
        return await self._owned(self._enrollment,raw)

    async def _enrollment(self,raw):
        _,state=await self._load()
        if state is None:fail('execution_not_found')
        await self._query_authorized(raw,state)
        if state['step']!='pending-enrollment' or state['enrollment'] is None:fail('execution_enrollment_unavailable')
        return canonical_bytes(state['enrollment'])

    async def dispatch(self,raw,*,task_inspection,native_evidence=None):
        self._native_ingress(native_evidence)
        return await self._owned(self._dispatch_start,raw,task_inspection,native_evidence)

    async def _dispatch_start(self,raw,inspection,native_evidence):
        async with self._dispatch:
            _,state=await self._load()
            if state is None or strict_loads(raw)!=state['originalEnvelope']:fail('execution_original_conflict')
            admission=await self._admission(state,native_evidence).recheck(inspection)
            if state['step']!='pending-enrollment' or state['executionPhase']!='start-intent':
                await self._native_disclosure(state,native_evidence)
                return self._view(state)
            binding=state['executionBinding'];cancel=binding['originalOperation']['cancellationRef']
            intent=RetainedContainerIntent(self._ledger,admission.binding)
            # C independently checks actual current enrollment before private use.
            # A failed or uncertain stage can only reconcile, never resume effects.
            state=await self._save('container-create-intent')
            observed=await self._adapter.prepare(admission,task_inspection=inspection,intent=intent)
            if observed.status!='prepared' or observed.resource_ref is None:fail('execution_create_uncertain')
            await self._save('container-prepared',resource=observed.resource_ref)
            delivery=await self._signer.credential('deliver',binding,(await self._credentials._ledger.current()).sequence,cancel)
            await self._save('delivery-intent')
            await self._credentials.deliver(delivery,admission,task_inspection=inspection,
                account_request=await self._signer.account(cancel),intent=intent)
            observed_raw=await self._signer.credential('observe',binding,(await self._credentials._ledger.current()).sequence,cancel)
            credential=strict_loads(await self._credentials.observe(observed_raw))
            if credential['phase']!='delivered':fail('execution_delivery_uncertain')
            await self._save('credential-delivered')
            await self._save('proof-intent')
            await self._credentials.inspect_task(delivery,admission,task_inspection=inspection,
                account_request=await self._signer.account(cancel),intent=intent)
            await self._save('proved')
            admission=await admission.recheck(inspection)
            await self._save('start-effect-intent')
            observed=await self._adapter.start(binding['runRef'],admission,task_inspection=inspection,intent=intent)
            phase='running' if observed.status=='running' else 'terminal' if observed.status=='terminal' else 'unknown'
            state=await self._save(phase,phase=phase,resource=observed.resource_ref)
            await admission.recheck(inspection)
            await self._native_disclosure(state,native_evidence)
            return self._view(state)

    async def _query_authorized(self,raw,state):
        env,end=await self._authorize(raw,'execution-run-observe',service=True)
        if env['payload']!={'runRef':state['executionBinding']['runRef']}:fail('execution_run_selection')
        return env,end

    async def query(self,raw):return await self._owned(self._query,raw)

    async def _query(self,raw):
        _,state=await self._load()
        if state is None:fail('execution_not_found')
        await self._query_authorized(raw,state)
        return self._view(state)

    async def _never_dispatched(self):
        snapshot,_=await self._load()
        return not any(strict_loads(item.record)['state']['step']=='container-create-intent' for item in snapshot.records)

    async def _physical(self,state):
        run=state['executionBinding']['runRef']
        try:return await self._adapter.observe(run)
        except ContractError as exc:
            if str(exc)!='execution_container_unknown':raise
        return await self._adapter.recover(RetainedContainerIntent(self._ledger,canonical_bytes(state['executionBinding'])),
            resource_ref=None if state['resourceRef'] is None else canonical_bytes(state['resourceRef']))

    async def reconcile(self,raw):return await self._owned(self._reconcile,raw)

    async def _reconcile(self,raw):
        _,state=await self._load()
        if state is None:fail('execution_not_found')
        await self._query_authorized(raw,state)
        async with self._dispatch:
            _,state=await self._load()
            if state['executionPhase']=='terminal':
                await self._query_authorized(raw,state)
                return self._view(state)
            if state['executionPhase']=='cancel-intent' and await self._never_dispatched():
                state=await self._save('terminal',phase='terminal')
                await self._query_authorized(raw,state)
                return self._view(state)
            observed=await self._physical(state)
            phase='terminal' if observed.status=='terminal' else 'cancel-intent' if state['executionPhase']=='cancel-intent' else 'unknown'
            # Stable observations do not consume another retained completion slot.
            state=await self._save(phase,phase=phase,resource=observed.resource_ref)
        await self._query_authorized(raw,state)
        return self._view(state)

    async def cancel(self,raw):return await self._owned(self._cancel,raw)

    async def _cancel(self,raw):
        async with self._gate:
            snapshot,state=await self._load()
            if state is None:fail('execution_not_found')
            env,end=await self._authorize(raw,'capability-process-cancel')
            binding=state['executionBinding'];op=env['operation']
            if (env['payload']!={'resourceRef':binding['executorRef'],'input':{'runRef':binding['runRef']}}
                    or op['expectedVersion']!=binding['executorRef']['revision']
                    or op['effectiveActorRef']!=binding['originalOperation']['effectiveActorRef']):fail('execution_cancel_binding')
            existing=next((strict_loads(item.record) for item in snapshot.records
                if strict_loads(item.record)['operation']['operationId']==op['operationId']),None)
            if existing is not None:
                if existing['operation']!=op:fail('execution_original_conflict')
                return self._view(state)
            if state['executionPhase']=='terminal':return self._view(state)
            if state['executionPhase']=='cancel-intent':return self._view(state)
            state={**state,'executionPhase':'cancel-intent','step':'cancel-intent'}
            await self._append(env,state,snapshot,end)
        # Join the original dispatch before stop. Saving cancel above fences B's
        # last current-intent check even while create/start is still in flight.
        async with self._dispatch:
            _,state=await self._load()
            await self._authorize(raw,'capability-process-cancel')
            if await self._never_dispatched():
                state=await self._save('terminal',phase='terminal')
                await self._authorize(raw,'capability-process-cancel')
                return self._view(state)
            observed=await self._physical(state)
            if observed.resource_ref is not None:
                await self._authorize(raw,'capability-process-cancel')
                observed=await self._adapter.stop(binding['runRef'])
            phase='terminal' if observed.status=='terminal' else 'cancel-intent'
            state=await self._save(phase,phase=phase,resource=observed.resource_ref)
        await self._authorize(raw,'capability-process-cancel')
        return self._view(state)

    async def retire(self,raw):return await self._owned(self._retire,raw)

    async def _retire(self,raw):
        async with self._dispatch:
            snapshot,state=await self._load()
            if state is None:fail('execution_not_found')
            await self._query_authorized(raw,state)
            never=await self._never_dispatched()
            observed=None if never else await self._physical(state)
            steps={strict_loads(item.record)['state']['step'] for item in snapshot.records}
            # A lost CREATE reply may leave a positively identified created
            # container. Pending is only eligibility to ask B for exact cleanup;
            # B still verifies nonrunning state, identity and joined users.
            created_candidate=(not never and state['executionPhase']=='cancel-intent'
                and observed.status=='pending' and observed.resource_ref is not None
                and 'container-create-intent' in steps and 'container-prepared' not in steps)
            if (not never and (observed.resource_ref is None or observed.status!='terminal' and not created_candidate)
                    or never and state['executionPhase']!='terminal'):fail('execution_physical_state_unresolved')
            binding=state['executionBinding'];cancel=binding['originalOperation']['cancellationRef']
            if state['step']=='retired':
                await self._query_authorized(raw,state)
                return self._view(state)
            if (await self._credentials._ledger.current()).sequence:
                command=await self._signer.credential('retire',binding,(await self._credentials._ledger.current()).sequence,cancel)
                await self._credentials.retire(command)
            # C has joined its private users before B joins the exact physical
            # relay and removes this container. No task reservation is released.
            await self._query_authorized(raw,state)
            if not never:
                await self._adapter.cleanup(binding['runRef'])
                confirmed=await self._adapter.observe(binding['runRef'])
                if confirmed.status!='terminal' or confirmed.resource_ref!=observed.resource_ref:
                    fail('execution_physical_state_unresolved')
            await self._query_authorized(raw,state)
            state=await self._save('retired',phase='terminal',resource=None if observed is None else observed.resource_ref)
            await self._query_authorized(raw,state)
            return self._view(state)

    async def close(self,*,timeout=5):
        self._closed=True
        if self._closing is None or (self._closing.done() and not self._closing.cancelled() and self._closing.exception() is not None):
            self._closing=asyncio.create_task(self._finish_close(timeout),name='execution-owner-checkpoint')
        return await asyncio.shield(self._closing)

    async def _finish_close(self,timeout):
        if self._jobs:
            _,pending=await asyncio.wait(tuple(self._jobs),timeout=timeout)
            if pending:fail('execution_users_not_joined')
        await self._credentials.close(timeout=timeout)
        return await self._adapter.checkpoint()
