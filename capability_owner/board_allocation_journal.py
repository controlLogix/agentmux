"""Retained prefix claims for the counter and first-card creation sequence."""
import asyncio
import base64
from datetime import datetime,timezone
import secrets

from agentmux_contracts import ContractError,canonical_bytes,payload_digest,strict_loads,validate
from identity.authority import LedgerAuthorityReader
from state_owner.ledger import MAX_RECORD_BYTES,OwnerLedger,StoredRecord,validate_record
from .board_allocation import BoardAllocationTarget,PreparedBoardAllocation
from .board_journal import PHASE_CONTRACTS,_same_operation,_valid_ref,candidate_digest,claim_identity,claim_marker


def _fail():
    raise ContractError('board_allocation_journal_invalid')


OWNER_PHASE_LIMIT=16_384
# A later record adds one bounded phase envelope and may replace the top-level
# operation with that envelope's operation. Another KiB covers the two fence
# IDs, observed revisions, phase name and closed completion observation.
ALLOCATION_CLAIM_LIMIT=MAX_RECORD_BYTES-2*OWNER_PHASE_LIMIT-1024


class BoardAllocationJournal:
    def __init__(self,ledger,authority,*,owner_service_identity_ref,target_binding):
        if (type(target_binding) is not BoardAllocationTarget or not isinstance(ledger,OwnerLedger)
                or not ledger.completion_budget_required or not isinstance(authority,LedgerAuthorityReader)
                or (ledger._binding.owner_domain,ledger._binding.entity_kind)!=('federation-board-operations','attempt')
                or strict_loads(ledger._binding.scope)['projectId'] is None
                or not _valid_ref(owner_service_identity_ref)
                or owner_service_identity_ref['ownerHubId']!=ledger._binding.hub_id):
            raise ContractError('board_allocation_configuration')
        self._ledger,self._authority,self._binding=ledger,authority,ledger._binding
        self._target,self._owner=target_binding,canonical_bytes(owner_service_identity_ref)
        self._lock=asyncio.Lock()
        self._observations={}

    def __repr__(self):
        return '<BoardAllocationJournal private>'

    async def _authorize(self,raw,contracts):
        if type(raw) is not bytes or len(raw)>65536:_fail()
        envelope=strict_loads(raw)
        if canonical_bytes(envelope)!=raw or envelope['contractId'] not in contracts:_fail()
        if envelope['contractId'] in PHASE_CONTRACTS and len(raw)>OWNER_PHASE_LIMIT:_fail()
        decision=await self._authority.evaluate(raw,audience={'hubId':self._binding.hub_id,'serviceId':'storage-owner'})
        if (decision.outcome!='allowed' or canonical_bytes(envelope['operation']['scope'])!=self._binding.scope
                or envelope['payload']['resourceRef']['id']!=self._binding.entity_id
                or envelope['payload']['resourceRef']['ownerHubId']!=self._binding.hub_id):
            raise ContractError('board_allocation_access_refused')
        if envelope['contractId'] in PHASE_CONTRACTS:
            operation=envelope['operation']
            if (operation['caller']['kind']!='service'
                    or canonical_bytes(operation['caller']['authenticatedIdentityRef'])!=self._owner
                    or canonical_bytes(operation['effectiveActorRef'])!=self._owner):
                raise ContractError('board_allocation_access_refused')
        elif envelope['payload']['input']['command']!='add':_fail()
        return envelope,decision

    def _ref(self,stored):
        return {'id':strict_loads(stored.record)['recordId'],'ownerHubId':self._binding.hub_id,'revision':stored.sequence}

    def _record(self,snapshot,envelope,state,identifier=None):
        operation=envelope['operation']
        return {'schemaVersion':'1.0.0','recordId':identifier or 'board-allocation-phase-'+secrets.token_hex(20),
            'entityId':self._binding.entity_id,'entityKind':'attempt','ownerHubId':self._binding.hub_id,
            'ownerDomain':self._binding.owner_domain,'entityVersion':len(snapshot.records)+1,
            'previousRevision':snapshot.sequence,'operation':operation,
            'recordedAt':datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z'),
            'outcome':'committed','state':state,'effects':[],'artifacts':[],'repository':None,
            'authorizationDecision':{'operationId':operation['operationId'],'decision':'allowed',
                'reason':'current_authority','actorRef':operation['effectiveActorRef'],'contractId':envelope['contractId']}}

    def _next(self,before,contract,observation,operation_id):
        phase=before['phase']
        changed={}
        if contract=='federation-board-dispatch':
            if observation is not None:_fail()
            if phase=='prepared':changed['phase']='counter-dispatching';remaining=8
            elif phase in ('counter-dispatching','counter-uncertain'):
                changed.update(phase='counter-recovering',counterFenceId=operation_id);remaining=6
            elif phase=='counter-settled':changed['phase']='card-dispatching';remaining=4
            elif phase in ('card-dispatching','card-uncertain'):
                changed.update(phase='card-recovering',cardFenceId=operation_id);remaining=2
            else:_fail()
        else:
            if observation is None:
                if phase=='counter-dispatching':changed['phase']='counter-uncertain';remaining=7
                elif phase=='card-dispatching':changed['phase']='card-uncertain';remaining=3
                else:_fail()
            elif type(observation) is not dict:_fail()
            elif observation.get('stage')=='abandon':
                if set(observation)!={'stage'} or phase not in ('prepared','counter-settled'):_fail()
                changed.update(phase='finished',outcome='rejected',auditDone=True,projectionDone=True);remaining=0
            elif observation.get('stage') in ('counter','card'):
                if (set(observation)!={'stage','outcome','revision'} or observation['outcome'] not in ('applied','rejected')
                        or type(observation['revision']) is not int or not 0<observation['revision']<=9007199254740991):_fail()
                revision=observation['revision']
                if observation['stage']=='counter':
                    if phase not in ('counter-dispatching','counter-uncertain','counter-recovering') or revision<=before['plan']['observedSequence']:_fail()
                    changed['counterRevision']=revision
                    if observation['outcome']=='applied':changed['phase']='counter-settled';remaining=5
                    else:changed.update(phase='finished',outcome='rejected',auditDone=True,projectionDone=True);remaining=0
                else:
                    if phase not in ('card-dispatching','card-uncertain','card-recovering') or revision<=before['counterRevision']:_fail()
                    changed['cardRevision']=revision
                    if observation['outcome']=='applied':changed.update(phase='card-settled',outcome='applied');remaining=1
                    else:changed.update(phase='finished',outcome='rejected',auditDone=True,projectionDone=True);remaining=0
            elif (set(observation)=={'stage','auditDone','projectionDone'} and observation['stage']=='finish'
                    and observation['auditDone'] is True and observation['projectionDone'] is True):
                if phase!='card-settled':_fail()
                changed.update(phase='finished',auditDone=True,projectionDone=True);remaining=0
            else:_fail()
        return changed,remaining

    def _read(self,snapshot):
        groups={}
        previous=None
        floor=self._target.stream_identity.minimum_sequence
        counter_head=None
        for stored in snapshot.records:
            record=validate_record(stored.record,self._binding)
            state=record['state']
            if (set(state)!={'format','original','claimId','targetBinding','plan','phase','phaseEnvelope',
                    'observation','counterRevision','cardRevision','outcome','auditDone','projectionDone','counterFenceId','cardFenceId'}
                    or state['format']!='amx-board-allocation-v1'
                    or canonical_bytes(state['targetBinding'])!=self._target.canonical
                    or record['outcome']!='committed' or record['effects'] or record['artifacts'] or record['repository'] is not None):_fail()
            original=state['original']
            validate('message-envelope',original)
            validate('federation-board-command',original['payload'])
            operation=original['operation']
            if (original['contractId']!='federation-board-command' or original['payload']['input']['command']!='add'
                    or operation['payloadDigest']!=payload_digest(original['payload'])
                    or canonical_bytes(operation['scope'])!=self._binding.scope
                    or original['payload']['resourceRef']['id']!=self._binding.entity_id
                    or original['payload']['resourceRef']['ownerHubId']!=self._binding.hub_id
                    or state['claimId']!=claim_identity(original)):_fail()
            plan=state['plan']
            if (type(plan) is not dict or set(plan)!={'counterRevision','counterValue','observedSequence','number',
                    'key','candidateBytes','candidateDigest','kinds','what'}
                    or type(plan['counterRevision']) is not int or plan['counterRevision']<0
                    or type(plan['observedSequence']) is not int
                    or not max(plan['counterRevision'],self._target.stream_identity.minimum_sequence)<=plan['observedSequence']<=9007199254740991
                    or type(plan['number']) is not int or not 1<=plan['number']<=9007199254740991
                    or plan['key']!=self._target.counter_prefix+'-'+str(plan['number'])
                    or type(plan['kinds']) is not list or any(type(k) is not str for k in plan['kinds'])
                    or plan['what']!='created'):_fail()
            try:
                value=None if plan['counterValue'] is None else base64.b64decode(plan['counterValue'],validate=True)
                candidate=base64.b64decode(plan['candidateBytes'],validate=True)
                card=strict_loads(candidate)
                if (value is not None and (len(value)>128 or base64.b64encode(value).decode()!=plan['counterValue'])
                        or base64.b64encode(candidate).decode()!=plan['candidateBytes']
                        or (plan['counterRevision']==0)!=(value is None)
                        or (0 if value is None else int(value))+1!=plan['number']
                        or candidate_digest(candidate)!=plan['candidateDigest']
                        or card['key']!=plan['key'] or card['rid']!=self._target.repository_id
                        or card['_agentmuxOperation']!=claim_marker(original)):_fail()
            except (ValueError,TypeError,KeyError):_fail()
            identifier=operation['operationId']
            if identifier not in groups:
                if (len(stored.record)>ALLOCATION_CLAIM_LIMIT
                        or previous is not None and previous['state']['phase']!='finished'
                        or plan['observedSequence']<floor or state['phase']!='prepared'
                        or state['phaseEnvelope'] is not None or state['observation'] is not None
                        or state['counterRevision'] is not None or state['cardRevision'] is not None or state['outcome'] is not None
                        or state['counterFenceId'] is not None or state['cardFenceId'] is not None
                        or state['auditDone'] is not False or state['projectionDone'] is not False
                        or record['recordId']!=state['claimId'] or record['operation']!=operation):_fail()
                if counter_head is not None and (plan['counterRevision'],value)!=counter_head:
                    raise ContractError('board_counter_recovery_required')
                counter_head=(plan['counterRevision'],value)
                groups[identifier]={'original':original,'claim':stored,'latest':stored,'state':state}
                contract='federation-board-command'
            else:
                group=groups[identifier]
                phase=state['phaseEnvelope']
                if previous is not group or type(phase) is not dict:_fail()
                validate('message-envelope',phase)
                validate(phase['contractId'],phase['payload'])
                if len(canonical_bytes(phase))>OWNER_PHASE_LIMIT:_fail()
                payload,op=phase['payload'],phase['operation']
                if (phase['contractId'] not in PHASE_CONTRACTS or op!=record['operation']
                        or op['caller']['kind']!='service' or canonical_bytes(op['caller']['authenticatedIdentityRef'])!=self._owner
                        or canonical_bytes(op['effectiveActorRef'])!=self._owner
                        or canonical_bytes(op['scope'])!=self._binding.scope
                        or op['expectedVersion']!=group['latest'].sequence
                        or op['operationId']==operation['operationId']
                        or op['payloadDigest']!=payload_digest(payload)
                        or payload['resourceRef']!=original['payload']['resourceRef']
                        or payload['claimRef']!=self._ref(group['claim'])
                        or payload['journalRef']!={'id':self._binding.entity_id,'ownerHubId':self._binding.hub_id,'revision':group['latest'].sequence}
                        or payload['originalOperationId']!=identifier or payload['originalPayloadDigest']!=operation['payloadDigest']
                        or payload['candidateDigest']!=plan['candidateDigest']):_fail()
                expected=strict_loads(canonical_bytes(group['state']))
                changed,_=self._next(expected,phase['contractId'],state['observation'],op['operationId'])
                expected.update(changed,phaseEnvelope=phase,observation=state['observation'])
                if canonical_bytes(expected)!=canonical_bytes(state):_fail()
                group.update(latest=stored,state=state)
                contract=phase['contractId']
            if record.get('authorizationDecision')!={'operationId':record['operation']['operationId'],'decision':'allowed',
                'reason':'current_authority','actorRef':record['operation']['effectiveActorRef'],'contractId':contract}:_fail()
            previous=groups[identifier]
            observation=state['observation']
            if type(observation) is dict and observation.get('stage')=='counter':
                counter_head=(state['counterRevision'],
                    str(plan['number']).encode() if observation['outcome']=='applied' else b'0' if value is None else value)
            floor=max(floor,plan['observedSequence'],state['counterRevision'] or 0,state['cardRevision'] or 0)
        return groups

    async def prepare(self,raw,*,expected_sequence,plan):
        async with self._lock:
            envelope,decision=await self._authorize(raw,{'federation-board-command'})
            snapshot=await self._ledger.current()
            groups=self._read(snapshot)
            prior=groups.get(envelope['operation']['operationId'])
            if prior is not None:
                if not _same_operation(prior['original'],envelope):raise ContractError('owner_operation_conflict')
                return StoredRecord(prior['claim'].record,prior['claim'].sequence,True)
            if (snapshot.sequence!=expected_sequence or type(plan) is not PreparedBoardAllocation
                    or plan.target.canonical!=self._target.canonical
                    or snapshot.latest is not None and strict_loads(snapshot.latest.record)['state']['phase']!='finished'):
                raise ContractError('board_allocation_busy')
            state={'format':'amx-board-allocation-v1','original':envelope,'claimId':claim_identity(envelope),
                'targetBinding':strict_loads(self._target.canonical),'plan':{'counterRevision':plan.counter_revision,
                'counterValue':None if plan.counter_value is None else base64.b64encode(plan.counter_value).decode(),
                'observedSequence':plan.observed_sequence,'number':plan.number,'key':plan.key,
                'candidateBytes':base64.b64encode(plan.candidate.value).decode(),
                'candidateDigest':candidate_digest(plan.candidate.value),'kinds':list(plan.candidate.kinds),'what':plan.candidate.what},
                'phase':'prepared','phaseEnvelope':None,'observation':None,'counterRevision':None,'cardRevision':None,
                'outcome':None,'auditDone':False,'projectionDone':False,'counterFenceId':None,'cardFenceId':None}
            record=self._record(snapshot,envelope,state,state['claimId'])
            if len(canonical_bytes(record))>ALLOCATION_CLAIM_LIMIT:
                raise ContractError('board_allocation_capacity')
            self._read(type(snapshot)((*snapshot.records,StoredRecord(canonical_bytes(record),snapshot.sequence+1)),snapshot.sequence+1))
            _,decision=await self._authorize(raw,{'federation-board-command'})
            return await self._ledger.append(record,expected_sequence=snapshot.sequence,
                expected_target_version=envelope['operation']['expectedVersion'],valid_until=decision.valid_until,completion_records=9)

    def _observe(self,claim_ref,*,result):
        identifier='allocation-observation-'+secrets.token_hex(20)
        self._observations[identifier]=(canonical_bytes(claim_ref),canonical_bytes(result))
        return identifier

    async def advance(self,raw,*,expected_sequence):
        async with self._lock:
            envelope,decision=await self._authorize(raw,PHASE_CONTRACTS)
            snapshot=await self._ledger.current()
            groups=self._read(snapshot)
            replay=await self._ledger.outcome(envelope['operation']['operationId'],envelope['operation']['payloadDigest'])
            if replay is not None:
                if not _same_operation(strict_loads(replay.record)['state']['phaseEnvelope'],envelope):raise ContractError('owner_operation_conflict')
                if envelope['contractId']=='federation-board-complete':self._observations.pop(envelope['payload']['observationId'],None)
                return replay
            payload=envelope['payload']
            group=groups.get(payload['originalOperationId'])
            if snapshot.sequence!=expected_sequence or group is None:_fail()
            observation=None
            if envelope['contractId']=='federation-board-complete':
                held=self._observations.get(payload['observationId'])
                if held is None or held[0]!=canonical_bytes(payload['claimRef']):raise ContractError('board_observation_unavailable')
                observation=strict_loads(held[1])
            state=strict_loads(canonical_bytes(group['state']))
            changed,remaining=self._next(state,envelope['contractId'],observation,envelope['operation']['operationId'])
            state.update(changed,phaseEnvelope=envelope,observation=observation)
            record=self._record(snapshot,envelope,state)
            self._read(type(snapshot)((*snapshot.records,StoredRecord(canonical_bytes(record),snapshot.sequence+1)),snapshot.sequence+1))
            _,decision=await self._authorize(raw,PHASE_CONTRACTS)
            stored=await self._ledger.append(record,expected_sequence=snapshot.sequence,
                expected_target_version=envelope['operation']['expectedVersion'],valid_until=decision.valid_until,
                admission='reconciliation' if envelope['contractId']=='federation-board-complete' and observation is None else 'completion',
                completion_records=remaining)
            if envelope['contractId']=='federation-board-complete':self._observations.pop(payload['observationId'],None)
            return stored

    async def pending(self):
        groups=self._read(await self._ledger.current())
        if not groups:return None
        group=next(reversed(groups.values()))
        return None if group['state']['phase']=='finished' else group

    async def check_card(self,key):
        group=await self.pending()
        if group is not None and group['state']['plan']['key']==key:
            raise ContractError('board_allocation_pending')
