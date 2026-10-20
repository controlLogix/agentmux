"""Owner-only counter and first-card effects, with retained prefix fencing."""
import asyncio
import base64
from datetime import datetime,timezone
from dataclasses import dataclass

from agentmux_contracts import ContractError,canonical_bytes,strict_loads,validate
from nats.js.errors import NotFoundError
from identity.authority import evaluate_snapshot
from .board_allocation import BoardAllocationResource,prepare_allocation
from .board_allocation_journal import BoardAllocationJournal
from .board_journal import PHASE_CONTRACTS,_same_operation
from .board_owner import BoardActor,BoardMutationOwner
from .board_phase_signer import BoardPhaseSigner


@dataclass(frozen=True,repr=False)
class _BoardHead:
    subject: str
    seq: int
    data: bytes
    headers: dict | None


class BoardAllocationOwner:
    def __init__(self,resource,journal,phase_signer,*,actors):
        if (type(resource) is not BoardAllocationResource or type(journal) is not BoardAllocationJournal
                or type(phase_signer) is not BoardPhaseSigner or phase_signer._journal is not journal
                or resource.binding.hub_id!=journal._binding.hub_id
                or resource.binding.entity_id!=journal._binding.entity_id
                or resource.binding.scope!=journal._binding.scope or resource.target.canonical!=journal._target.canonical
                or type(actors) is not tuple or not 1<=len(actors)<=64
                or any(type(actor) is not BoardActor for actor in actors)
                or len({(a.identity_ref,a.transport_ref) for a in actors})!=len(actors)):
            raise ContractError('board_allocation_configuration')
        self._resource,self._journal,self._phases=resource,journal,phase_signer
        self._actors=actors
        self._workers=set()
        self._originals={}
        self._recovery=None
        self._closed=False

    def __repr__(self):return '<BoardAllocationOwner private>'

    async def close(self,*,timeout=5):
        self._closed=True
        if self._workers:
            _,pending=await asyncio.wait(tuple(self._workers),timeout=timeout)
            if pending:raise ContractError('board_owner_cleanup_incomplete')

    async def _owned(self,coroutine):
        if self._closed or len(self._workers)>=32:
            coroutine.close()
            raise ContractError('board_allocation_unavailable')
        worker=asyncio.create_task(coroutine)
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _group(self,operation):
        groups=self._journal._read(await self._journal._ledger.current())
        group=groups.get(operation['operationId'])
        if group is None or group['original']['operation']['payloadDigest']!=operation['payloadDigest']:
            raise ContractError('board_allocation_outcome_conflict')
        return group

    def _floor(self,snapshot):
        groups=self._journal._read(snapshot)
        return max((self._resource.target.stream_identity.minimum_sequence,*(max(g['state']['plan']['observedSequence'],
            g['state']['counterRevision'] or 0,g['state']['cardRevision'] or 0) for g in groups.values())))

    async def _head(self,subject):
        floor=self._floor(await self._journal._ledger.current())
        await self._resource._stream(floor)
        try:
            entry=await self._resource._jetstream.get_msg('KV_am_board',subject=subject,direct=False)
        except NotFoundError:
            entry=None
        await self._resource._stream(floor)
        if entry is not None and (entry.subject!=subject or type(entry.seq) is not int
                or not 0<entry.seq<=self._resource._sequence
                or entry.headers is not None and not isinstance(entry.headers,dict)):
            raise ContractError('board_allocation_source_recovery_required')
        if entry is None:return None
        data=entry.data
        # The pinned client's non-direct API maps an omitted/empty body to
        # None. Accept that shape only for an explicit retained KV tombstone;
        # missing business data must still refuse recovery.
        if data is None and (entry.headers or {}).get('KV-Operation') in ('DEL','PURGE'):
            data=b''
        if type(data) is not bytes or len(data)>45000:
            raise ContractError('board_allocation_source_recovery_required')
        return _BoardHead(entry.subject,entry.seq,data,None if entry.headers is None else dict(entry.headers))

    def _headers(self,group,stage,*,fence=False):
        state=group['state']
        original=group['original']['operation']
        result={'Agentmux-Board-Claim':state['claimId'],'Agentmux-Board-Operation':original['operationId'],
            'Agentmux-Board-Digest':original['payloadDigest'],'Agentmux-Board-Stage':stage}
        if fence:
            result['Agentmux-Board-Fence']=state['counterFenceId' if stage=='counter-fence' else 'cardFenceId']
        return result

    @staticmethod
    def _matches(entry,headers):
        return entry is not None and all((entry.headers or {}).get(k)==v for k,v in headers.items())

    async def _publish(self,subject,value,revision,headers):
        floor=self._resource._sequence
        self._resource._current()
        ack=await self._resource._jetstream.publish(subject,value,headers={**headers,
            'Nats-Expected-Stream':'KV_am_board','Nats-Expected-Last-Subject-Sequence':str(revision)})
        if ack.stream!='KV_am_board' or type(ack.seq) is not int or not floor<ack.seq<=9007199254740991:
            raise ContractError('board_allocation_outcome_uncertain')
        return ack.seq

    async def _execution_authority(self,raw,group):
        # Evaluate the caller and recorded owner dispatch against one current
        # snapshot, without an await between either check and publication.
        snapshot=await self._journal._authority.current()
        now=datetime.now(timezone.utc)
        phase=group['state']['phaseEnvelope']
        if phase is None or phase['contractId']!='federation-board-dispatch':
            raise ContractError('board_allocation_access_refused')
        for envelope in (raw,canonical_bytes(phase)):
            decision=evaluate_snapshot(snapshot,envelope,audience={
                'hubId':self._journal._binding.hub_id,'serviceId':'storage-owner'},now=now)
            if decision.outcome!='allowed':raise ContractError('board_allocation_access_refused')
        self._resource._current()

    async def _phase(self,contract,group,*,observation=None,admit_only=False):
        snapshot=await self._journal._ledger.current()
        state=group['state']
        original=group['original']['operation']
        payload={'resourceRef':group['original']['payload']['resourceRef'],
            'journalRef':{'id':self._journal._binding.entity_id,'ownerHubId':self._journal._binding.hub_id,'revision':snapshot.sequence},
            'claimRef':self._journal._ref(group['claim']),'originalOperationId':original['operationId'],
            'originalPayloadDigest':original['payloadDigest'],'candidateDigest':state['plan']['candidateDigest']}
        if contract=='federation-board-complete':payload['observationId']=self._journal._observe(payload['claimRef'],result=observation)
        admitted=await self._phases.admit(contract,expected_sequence=snapshot.sequence,payload=payload,
            cancellation_ref=original['cancellationRef'])
        if admit_only:
            await self._journal._authorize(admitted.envelope,PHASE_CONTRACTS)
            return
        try:
            await self._journal.advance(admitted.envelope,expected_sequence=snapshot.sequence)
        except ContractError as error:
            if str(error)!='owner_commit_uncertain':raise
            await self._journal.advance(admitted.envelope,expected_sequence=snapshot.sequence)
        return await self._group(original)

    async def _uncertain(self,group):
        if group['state']['phase'] in ('counter-dispatching','card-dispatching'):
            await self._phase('federation-board-complete',group,observation=None)
        raise ContractError('board_allocation_outcome_uncertain')

    def _card_subject(self,group):
        return '$KV.am_board.'+self._resource.repository_id+'.card.'+group['state']['plan']['key']

    async def apply(self,raw):return await self._owned(self._apply(raw))

    async def _apply(self,raw):
        envelope,_=await self._journal._authorize(raw,{'federation-board-command'})
        by=BoardMutationOwner._actor(self,envelope)
        operation=envelope['operation']
        key=(operation['operationId'],operation['payloadDigest'])
        other=self._originals.get(key)
        if other is not None:
            if not _same_operation(other[0],envelope):raise ContractError('owner_operation_conflict')
            result=await asyncio.shield(other[1])
            await self._journal._authorize(raw,{'federation-board-command'})
            self._resource._current()
            return result
        task=asyncio.current_task()
        self._originals[key]=(envelope,task)
        try:
            snapshot=await self._journal._ledger.current()
            groups=self._journal._read(snapshot)
            group=groups.get(operation['operationId'])
            if group is not None:
                if not _same_operation(group['original'],envelope):raise ContractError('owner_operation_conflict')
            else:
                if snapshot.latest is not None and strict_loads(snapshot.latest.record)['state']['phase']!='finished':
                    raise ContractError('board_allocation_busy')
                # Retain this exact worker through the legacy local-card lookup.
                prepared=await asyncio.to_thread(self._resource.board._operations.prepare_add_input,envelope['payload']['input'])
                counter=await self._head(self._resource.target.counter_subject)
                if counter is not None and (counter.headers or {}).get('KV-Operation') is not None:
                    raise ContractError('board_counter_recovery_required')
                plan=prepare_allocation(self._resource.target,envelope,prepared,
                    counter_revision=0 if counter is None else counter.seq,counter_value=None if counter is None else counter.data,
                    observed_sequence=self._resource._sequence,context=self._resource._current(),by=by,
                    at=datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'))
                await self._journal.prepare(raw,expected_sequence=snapshot.sequence,plan=plan)
                group=await self._group(operation)
            result=await self._continue(group,raw)
            await self._journal._authorize(raw,{'federation-board-command'})
            self._resource._current()
            return result
        finally:
            if self._originals.get(key,(None,None))[1] is task:self._originals.pop(key,None)

    def _result(self,group):
        result=self._outcome(group)
        if result['outcome']!='applied':raise ContractError('board_allocation_rejected')
        return {**result['card'],'rev':result['cardRef']['revision'],
                'cardRef':result['cardRef'],'receiptRef':result['receiptRef']}

    def _outcome(self,group):
        state=group['state']
        if state['phase']!='finished':raise ContractError('board_allocation_outcome_uncertain')
        target=state['targetBinding']
        # This is the native board target, not an enrolled per-card capability
        # alias. Its real KV revision is separate from the journal receipt.
        card_ref=None if state['outcome']!='applied' else {'ownerHubId':self._resource.binding.hub_id,
            **{key:target[key] for key in ('bucket','repositoryId','domain','streamCreated')},
            'key':state['plan']['key'],'revision':state['cardRevision']}
        return {'outcome':state['outcome'],'cardRef':card_ref,'receiptRef':self._journal._ref(group['latest']),
            'card':None if card_ref is None else strict_loads(base64.b64decode(state['plan']['candidateBytes']))}

    async def _authorize_query(self,raw):
        if type(raw) is not bytes or len(raw)>65536:raise ContractError('board_allocation_query_refused')
        envelope=strict_loads(raw)
        validate('message-envelope',envelope)
        validate('capability-outcome-query',envelope['payload'])
        decision=await self._journal._authority.evaluate(raw,audience={
            'hubId':self._resource.binding.hub_id,'serviceId':'outcome-owner'})
        if (canonical_bytes(envelope)!=raw or envelope['contractId']!='capability-outcome-query'
                or decision.outcome!='allowed' or canonical_bytes(envelope['operation']['scope'])!=self._resource.binding.scope
                or envelope['payload']['resourceRef']['id']!=self._resource.binding.entity_id
                or envelope['payload']['resourceRef']['ownerHubId']!=self._resource.binding.hub_id
                or envelope['payload']['input']['contractId']!='federation-board-command'):
            raise ContractError('board_allocation_query_refused')
        self._resource._current()
        return envelope

    async def reconcile(self,raw):
        """Fresh authorized lookup; recovery never revives the original add."""
        return await self._owned(self._reconcile(raw))

    async def _reconcile(self,raw):
        query=await self._authorize_query(raw)
        original=query['payload']['input']
        groups=self._journal._read(await self._journal._ledger.current())
        group=groups.get(original['operationId'])
        result=None
        if group is not None:
            retained=group['original']['operation']
            if (retained['payloadDigest']!=original['payloadDigest']
                    or retained['caller']['authenticatedIdentityRef']!=query['operation']['caller']['authenticatedIdentityRef']
                    or retained['effectiveActorRef']!=query['operation']['effectiveActorRef']):
                raise ContractError('board_allocation_query_refused')
            if group['state']['phase']!='finished':
                await self.recover_pending()
                group=await self._group(original)
            result=self._outcome(group)
        await self._authorize_query(raw)
        return result

    async def _continue(self,group,raw):
        state=group['state']
        if state['phase']=='finished':return self._result(group)
        if state['phase']=='prepared':
            # The claim must already exclude competing allocations when this
            # collision check observes the exact latest card subject.
            if await self._head(self._card_subject(group)) is not None:
                await self._phase('federation-board-complete',group,observation={'stage':'abandon'})
                raise ContractError('board_allocation_collision')
            group=await self._phase('federation-board-dispatch',group)
            await self._execution_authority(raw,group)
            try:
                revision=await self._publish(self._resource.target.counter_subject,
                    str(state['plan']['number']).encode(),state['plan']['counterRevision'],self._headers(group,'counter'))
            except Exception:return await self._uncertain(group)
            group=await self._phase('federation-board-complete',group,
                observation={'stage':'counter','outcome':'applied','revision':revision})
        state=group['state']
        if state['phase']=='counter-settled':
            if await self._head(self._card_subject(group)) is not None:
                await self._phase('federation-board-complete',group,observation={'stage':'abandon'})
                raise ContractError('board_allocation_collision')
            group=await self._phase('federation-board-dispatch',group)
            await self._execution_authority(raw,group)
            try:
                revision=await self._publish(self._card_subject(group),base64.b64decode(state['plan']['candidateBytes']),0,
                    self._headers(group,'card'))
            except Exception:return await self._uncertain(group)
            group=await self._phase('federation-board-complete',group,
                observation={'stage':'card','outcome':'applied','revision':revision})
        if group['state']['phase']=='card-settled':return await self._finish(group)
        if group['state']['phase']=='finished':return self._result(group)
        group=await self._recover(group,resume=True)
        if group['state']['phase']=='counter-settled':return await self._continue(group,raw)
        return self._result(group)

    def _audit_once(self,owner,card,group,kinds,what):
        return BoardMutationOwner._audit_once(self,owner,card,group,kinds,what,card_key=group['state']['plan']['key'])

    async def _finish(self,group):
        state=group['state']
        if state['phase']=='finished':return self._result(group)
        head=await self._head(self._card_subject(group))
        candidate=base64.b64decode(state['plan']['candidateBytes'])
        if head is None or head.seq!=state['cardRevision'] or head.data!=candidate or (head.headers or {}).get('KV-Operation') is not None:
            return await self._uncertain(group)
        owner=self._resource._current()
        card=strict_loads(candidate)
        await owner.db(self._audit_once,owner,card,group,state['plan']['kinds'],state['plan']['what'])
        await owner.db(self._resource.board._operations._mirror,owner,self._resource.repository_id,state['plan']['key'],card,state['cardRevision'])
        group=await self._phase('federation-board-complete',group,
            observation={'stage':'finish','auditDone':True,'projectionDone':True})
        return self._result(group)

    async def recover_pending(self):
        """Host maintenance only: settle/fence retained work, never add a card."""
        if self._recovery is not None and not self._recovery.done():
            return await asyncio.shield(self._recovery)
        async def recover():
            group=await self._journal.pending()
            if group is None:return None
            operation=group['original']['operation']
            other=self._originals.get((operation['operationId'],operation['payloadDigest']))
            if other is not None and other[1] is not asyncio.current_task():
                try:
                    await asyncio.shield(other[1])
                except ContractError:
                    pass
                group=await self._group(operation)
            if group['state']['phase']!='finished':group=await self._recover(group)
            return {'outcome':group['state']['outcome'],'counterRevision':group['state']['counterRevision'],
                    'cardRevision':group['state']['cardRevision'],'receiptRef':self._journal._ref(group['latest'])}
        # Store the actual worker before yielding so concurrent maintenance joins
        # the same publication and readers rather than replacing an owned fence.
        if self._closed or len(self._workers)>=32:raise ContractError('board_allocation_unavailable')
        self._recovery=asyncio.create_task(recover())
        self._workers.add(self._recovery)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        self._recovery.add_done_callback(finished)
        return await asyncio.shield(self._recovery)

    async def _recovery_authority(self,group):
        # Reconciliation can fence an old dispatch under a fresh enrolled owner
        # grant. This permission never revives the expired caller's add command.
        await self._phase('federation-board-dispatch',group,admit_only=True)
        self._resource._current()

    async def _recover(self,group,*,resume=False):
        state=group['state']
        if state['phase']=='finished':return group
        if state['phase'] in ('prepared','counter-settled'):
            return await self._phase('federation-board-complete',group,observation={'stage':'abandon'})
        if state['phase']=='card-settled':
            await self._finish(group)
            return await self._group(group['original']['operation'])
        counter_stage=state['phase'].startswith('counter-')
        if state['phase'] in ('counter-dispatching','counter-uncertain','card-dispatching','card-uncertain'):
            group=await self._phase('federation-board-dispatch',group)
        state=group['state']
        if counter_stage:
            subject=self._resource.target.counter_subject
            before=None if state['plan']['counterValue'] is None else base64.b64decode(state['plan']['counterValue'])
            fence_value=b'0' if before is None else before
            business=self._headers(group,'counter')
            fence=self._headers(group,'counter-fence',fence=True)
            entry=await self._head(subject)
            async def observed(head):
                if (self._matches(head,business) and head.data==str(state['plan']['number']).encode()
                        and (head.headers or {}).get('KV-Operation') is None
                        and head.seq>state['plan']['observedSequence']):
                    settled=await self._phase('federation-board-complete',group,
                        observation={'stage':'counter','outcome':'applied','revision':head.seq})
                    if resume:return settled
                    # A maintenance query cannot start an undispatched card.
                    return await self._phase('federation-board-complete',settled,observation={'stage':'abandon'})
                if (self._matches(head,fence) and head.data==fence_value
                        and (head.headers or {}).get('KV-Operation') is None
                        and head.seq>state['plan']['observedSequence']):
                    return await self._phase('federation-board-complete',group,
                        observation={'stage':'counter','outcome':'rejected','revision':head.seq})
                return None
            settled=await observed(entry)
            if settled is not None:return settled
            unchanged=(entry is None and state['plan']['counterRevision']==0
                or entry is not None and entry.seq==state['plan']['counterRevision']
                and entry.data==before and (entry.headers or {}).get('KV-Operation') is None)
            if not unchanged:return await self._uncertain(group)
            await self._recovery_authority(group)
            try:
                revision=await self._publish(subject,fence_value,state['plan']['counterRevision'],fence)
            except Exception:
                settled=await observed(await self._head(subject))
                if settled is not None:return settled
                return await self._uncertain(group)
            return await self._phase('federation-board-complete',group,
                observation={'stage':'counter','outcome':'rejected','revision':revision})
        subject=self._card_subject(group)
        candidate=base64.b64decode(state['plan']['candidateBytes'])
        fence={**self._headers(group,'card-fence',fence=True),'KV-Operation':'DEL'}
        entry=await self._head(subject)
        async def observed(head):
            if (head is not None and head.data==candidate and head.seq>state['counterRevision']
                    and (head.headers or {}).get('KV-Operation') is None):
                settled=await self._phase('federation-board-complete',group,
                    observation={'stage':'card','outcome':'applied','revision':head.seq})
                await self._finish(settled)
                return await self._group(group['original']['operation'])
            if (self._matches(head,fence) and head.data==b'' and head.seq>state['counterRevision']
                    and (head.headers or {}).get('Nats-Rollup') is None):
                return await self._phase('federation-board-complete',group,
                    observation={'stage':'card','outcome':'rejected','revision':head.seq})
            return None
        settled=await observed(entry)
        if settled is not None:return settled
        if entry is not None:return await self._uncertain(group)
        await self._recovery_authority(group)
        try:
            # An ordinary retained tombstone, never purge/rollup or KV.create.
            # Expected subject sequence zero fences the late first creation.
            revision=await self._publish(subject,b'',0,fence)
        except Exception:
            settled=await observed(await self._head(subject))
            if settled is not None:return settled
            return await self._uncertain(group)
        return await self._phase('federation-board-complete',group,
            observation={'stage':'card','outcome':'rejected','revision':revision})
