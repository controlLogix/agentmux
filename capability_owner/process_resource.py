"""Closed Process capability mapping over the selected retained execution owner."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import secrets

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key
from identity.capability_routes import CAPABILITY_DESTINATIONS
from identity.capability_service import evaluate_capability_service_request
from identity.execution_evidence import NativeExecutionEvidence
from identity.ingress import EnrolledIngress
from state_owner.ledger import OwnerBinding
from .process_admission import ProcessRunAdmission, business


def fail(code='capability_access_refused'):raise ContractError(code) from None


class ProcessInspectionSigner:
    """The host's enrolled service can request only its selected task inspection."""
    def __init__(self,ingress,*,transport_ref,grant_ref,signing_seed):
        if type(ingress) is not EnrolledIngress or ingress._session_authorizer is not None or type(signing_seed) is not bytes or len(signing_seed)!=32:fail()
        for ref in (transport_ref,grant_ref):validate('execution-plan-read',{'planRef':ref})
        self._ingress,self._transport,self._grant,self._seed=ingress,canonical_bytes(transport_ref),canonical_bytes(grant_ref),signing_seed

    def __repr__(self):return '<ProcessInspectionSigner private>'

    async def inspect(self,admission):
        reader=self._ingress._reader
        if type(admission) is not ProcessRunAdmission or admission._plans._authority is not reader:fail()
        now=datetime.now(timezone.utc)
        stamp=lambda t:t.isoformat(timespec='microseconds').replace('+00:00','Z')
        claims={'purpose':'agentmux-client-possession-v1','hubId':reader._hub,'profileId':reader._profile,
            'authorityId':reader._entity,'transportRef':strict_loads(self._transport),'grantRef':strict_loads(self._grant),
            'operationId':'process-inspect-'+secrets.token_hex(20),'expectedVersion':0,'contractId':'task-inspect',
            'payload':{'taskId':admission._plans._task._ledger._binding.entity_id},'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        result=await self._ingress.admit(canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
            'signature':sign_claims(claims,self._seed)}),cancellation_ref=strict_loads(admission._plans._executor))
        if result.decision.outcome!='allowed' or result.envelope is None:fail()
        if strict_loads(result.envelope)['operation']['caller']['kind']!='service':fail()
        return result.envelope


class ProcessResource:
    """One executor/plan selection; public replies expose references and outcomes."""
    def __init__(self,admission,inspection,*,plugin_identity,instance_id,package_id,terminal_owner=None):
        if (type(admission) is not ProcessRunAdmission or type(inspection) is not ProcessInspectionSigner
                or inspection._ingress._reader is not admission._plans._authority):fail()
        validate('execution-plan-read',{'planRef':plugin_identity})
        self._admission,self._inspection=admission,inspection
        self._reader=admission._plans._authority
        self._executor=strict_loads(admission._plans._executor)
        self.binding=OwnerBinding(self._reader._hub,'execution',self._executor['id'],'attempt',admission._plans._ledger._binding.scope)
        self._plugin=canonical_bytes(plugin_identity);self._instance,self._package=instance_id,package_id
        self._terminal=terminal_owner
        self._closed=False;self._workers=set();self._gate=asyncio.Lock()

    def __repr__(self):return '<ProcessResource private>'

    def _current(self):
        if self._closed:fail('capability_process_unavailable')
        self._admission.current()

    def check_request(self,snapshot,claims):
        self._current()
        rows=[row for row in strict_loads(snapshot.record)['state'].get('nativeInstances',[]) if row['owner']==claims['owner']]
        if (len(rows)!=1 or canonical_bytes(rows[0]['identityRef'])!=self._plugin
                or rows[0]['owner']['instanceId']!=self._instance or rows[0]['owner']['pin']['packageId']!=self._package
                or claims['resourceRef']!=self._executor or canonical_bytes(claims['scope'])!=self.binding.scope):fail()

    async def authorize(self,authority,raw,service_raw):
        self._current()
        if authority is not self._reader or type(service_raw) is not bytes:fail()
        packet=strict_loads(service_raw);validate('capability-service-request',packet)
        if canonical_bytes(packet)!=service_raw or base64.b64decode(packet['claims']['envelopeBytes'],validate=True)!=raw:fail()
        envelope=strict_loads(raw);contract=envelope['contractId']
        if contract not in ('capability-process-start','capability-process-cancel','capability-outcome-query'):fail()
        if contract=='capability-outcome-query' and envelope['payload']['input']['contractId'] not in ('capability-process-start','capability-process-cancel'):fail()
        async def current():
            snapshot=await authority.current()
            decision=evaluate_capability_service_request(snapshot,service_raw,
                service_id=CAPABILITY_DESTINATIONS[contract],now=datetime.now(timezone.utc))
            self.check_request(snapshot,packet['claims'])
            return decision
        await current()
        await self._admission._plans._ingress.authorize_terminal(envelope['operation'])
        return await current()

    def _evidence(self,service_raw):
        return NativeExecutionEvidence(service_raw,self._admission._plans._ingress,self._plugin,
            self._instance,self._package,self._terminal)

    async def call(self,raw,service_raw):
        self._current()
        if len(self._workers)>=16:fail('capability_service_unavailable')
        original=asyncio.create_task(self._call(raw,service_raw),name='process-capability-owner')
        self._workers.add(original)
        def done(task):
            self._workers.discard(task)
            if not task.cancelled():task.exception()
        original.add_done_callback(done)
        return await asyncio.shield(original)

    async def _call(self,raw,service_raw):
        await self.authorize(self._reader,raw,service_raw)
        envelope=strict_loads(raw);contract=envelope['contractId']
        async with self._gate:
            self._current()
            if contract=='capability-process-start':
                inspection=await self._inspection.inspect(self._admission)
                evidence=self._evidence(service_raw)
                owner=await self._admission.open(raw,task_inspection=inspection,native_evidence=evidence)
                snapshot,state=await owner._load()
                original=raw if state is None else canonical_bytes(state['originalEnvelope'])
                result=strict_loads(await owner.start(original,task_inspection=inspection,native_evidence=evidence))
                snapshot,state=await owner._load()
                if state['step']=='pending-enrollment' and await self._enrolled(state):
                    result=strict_loads(await owner.dispatch(original,task_inspection=inspection,native_evidence=evidence))
                answer={'receiptRef':state['executionBinding']['runRef'],
                    'outcome':'uncertain' if result['status'] in ('unknown','pending') else 'accepted'}
            else:
                owner=await self._admission.existing()
                if owner is None:
                    if contract!='capability-outcome-query':fail()
                    answer=self._outcome(envelope,None)
                else:
                    snapshot,state=await owner._load()
                    if state['executionBinding']['originalOperation']['effectiveActorRef']!=envelope['operation']['effectiveActorRef']:fail()
                    if contract=='capability-process-cancel':
                        result=strict_loads(await owner.cancel(raw))
                        answer={'receiptRef':state['executionBinding']['runRef'],
                            'outcome':'stopped' if result['status']=='terminal' else 'uncertain' if result['status']=='unknown' else 'pending'}
                    else:answer=self._outcome(envelope,snapshot)
        await self.authorize(self._reader,raw,service_raw)
        validate(contract+'-reply',answer)
        return answer

    async def _enrolled(self,state):
        record=state['enrollment']['record']
        snapshot=await self._reader.current();value=strict_loads(snapshot.record)
        index=_indexes(value['state'],value['ownerHubId']);now=datetime.now(timezone.utc)
        transport=index['transports'].get(_key(record['transportRef']))
        if transport is None:return False
        # C checks the full enrollment and current worker/read/account policy again
        # before private delivery. This check only avoids premature container work.
        if not _active(transport,now) or transport['identityRef']!=record['workerIdentityRef'] or transport['issuerRef']!=record['identityIssuerRef']:fail()
        return True

    def _outcome(self,envelope,snapshot):
        query=envelope['payload']['input'];selected=None
        if snapshot is not None:
            for item in snapshot.records:
                record=strict_loads(item.record);operation=record['operation']
                if operation['operationId']!=query['operationId']:continue
                if (operation['payloadDigest']!=query['payloadDigest']
                        or record['authorizationDecision']['contractId']!=query['contractId']
                        or operation['effectiveActorRef']!=envelope['operation']['effectiveActorRef']):fail('capability_outcome_conflict')
                selected={'id':self._admission._ledger._binding.entity_id,'ownerHubId':self.binding.hub_id,'revision':item.sequence}
        return {'operationId':query['operationId'],'payloadDigest':query['payloadDigest'],
            'recordRef':selected,'outcome':'absent' if selected is None else 'committed'}

    async def close(self):
        self._closed=True
        if self._workers:await asyncio.gather(*tuple(self._workers),return_exceptions=True)
        await self._admission.close()
