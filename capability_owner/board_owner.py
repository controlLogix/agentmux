"""Trusted board mutation backend; network composition remains host-owned.

The qualified host must admit every card writer through this owner and restrict
broker publication. This backend does not install credentials or change a legacy
account. CapabilityReceiver requires an explicit publisher-issued route before
exposing this backend through the shared storage contracts.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.fed import ledger as federation_ledger
from hub.fed.board_services import BUCKET, RETRIES, PreparedBoardChange, _validate_board_change
from hub.fed.plugins.messages import parse_peer_address
from .board_journal import BoardOperationJournal, ORIGINAL_CONTRACTS, claim_marker, candidate_digest, _valid_ref, _same_operation
from identity.capability_service import evaluate_capability_service_request
from .board_phase_signer import BoardPhaseSigner
from .board_target import BoardTargetBinding
from .federation_board import FederationBoardResource


@dataclass(frozen=True, repr=False)
class BoardActor:
    identity_ref: bytes
    transport_ref: bytes
    address: str
    legacy_caller: str | None = None

    def __post_init__(self):
        for name in ('identity_ref','transport_ref'):
            value=getattr(self,name)
            value=strict_loads(value) if type(value) is bytes else value
            if not _valid_ref(value):
                raise ContractError('board_actor_configuration')
            object.__setattr__(self,name,canonical_bytes(value))
        parse_peer_address(self.address)
        if self.legacy_caller is not None and (type(self.legacy_caller) is not str or not self.legacy_caller):
            raise ContractError('board_actor_configuration')

    def __repr__(self):
        return '<BoardActor private>'


class BoardMutationOwner:
    def __init__(self, resource, journal, phase_signer, *, actors):
        if (not isinstance(resource,FederationBoardResource) or not isinstance(journal,BoardOperationJournal)
                or not isinstance(phase_signer,BoardPhaseSigner) or phase_signer._journal is not journal
                or resource.binding.entity_id != journal._binding.entity_id
                or resource.binding.hub_id != journal._binding.hub_id
                or resource.binding.scope != journal._binding.scope
                or type(actors) is not tuple or not 1 <= len(actors) <= 64
                or any(type(actor) is not BoardActor for actor in actors)
                or len({(a.identity_ref,a.transport_ref) for a in actors}) != len(actors)):
            raise ContractError('board_owner_configuration')
        expected_prefix='$JS.'+journal._target.domain+'.API' if journal._target.domain else '$JS.API'
        if getattr(resource._jetstream,'_prefix',None) != expected_prefix:
            raise ContractError('board_owner_configuration')
        target=BoardTargetBinding(resource.repository_id,resource.card_key,resource.stream_identity,journal._target.domain)
        if target.canonical != journal._target.canonical:
            raise ContractError('board_owner_configuration')
        self._resource,self._journal,self._phases=resource,journal,phase_signer
        self._actors=actors
        self._workers=set()
        self._originals={}
        self._closed=False
        self._allocation_gate=None

    def __repr__(self):
        return '<BoardMutationOwner private>'

    def _actor(self, envelope):
        operation=envelope['operation']
        transport=envelope['ingressAttestation']['claims']['authenticatedTransportRef']
        matches=[actor for actor in self._actors
            if actor.identity_ref==canonical_bytes(operation['effectiveActorRef'])
            and actor.transport_ref==canonical_bytes(transport)]
        if len(matches)!=1:
            raise ContractError('board_actor_unavailable')
        actor=matches[0]
        if envelope['contractId']=='federation-board-command':
            attribution=envelope['payload']['attribution']
            if actor.legacy_caller is None or (actor.legacy_caller!='operator' and attribution!=actor.legacy_caller):
                raise ContractError('board_actor_unavailable')
            # Only a protected operator bridge may preserve --as attribution.
            if actor.legacy_caller=='operator':
                sender=self._resource._current().sender_of(attribution)
                peer=parse_peer_address(actor.address)[0]
                if sender.get('operator'):
                    return 'peer:'+peer
                return f"peer:{peer}/{sender['repo']}/{sender['role']}/{sender['agent']}"
        return actor.address

    async def _entry(self, snapshot):
        groups=self._journal._read(snapshot)
        floor=self._journal._source_floor(groups)
        object.__setattr__(self._resource,'_sequence',max(self._resource._sequence,floor))
        await self._resource._stream()
        kv=await self._resource._key_value()
        key=self._resource.repository_id+'.card.'+self._resource.card_key
        entry=await kv.get(key)
        await self._resource._stream()
        self._resource._current()
        known=max((0,*(0 if g['state']['result'] is None else
                       g['state']['result']['resourceRef']['revision'] for g in groups.values())))
        if (entry.bucket!=BUCKET or entry.key!=key or type(entry.revision) is not int
                or entry.revision<known or type(entry.value) is not bytes or len(entry.value)>45000):
            raise ContractError('board_source_recovery_required')
        card=strict_loads(entry.value)
        if type(card) is not dict or card.get('rid')!=self._resource.repository_id or card.get('key')!=self._resource.card_key:
            raise ContractError('board_source_recovery_required')
        if self._allocation_gate is not None:
            await self._allocation_gate.check_card(self._journal._authority,self._resource)
        return kv,entry,card

    async def apply(self, raw, *, service_request_bytes=None):
        if self._closed or len(self._workers)>=32:
            raise ContractError('board_owner_unavailable')
        worker=asyncio.create_task(self._apply(raw,service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def close(self, *, timeout=5):
        self._closed=True
        if self._workers:
            _,pending=await asyncio.wait(tuple(self._workers),timeout=timeout)
            if pending:raise ContractError('board_owner_cleanup_incomplete')

    async def _phase(self, contract, group, *, observation=None):
        snapshot=await self._journal._ledger.current()
        state=group['state']
        operation=group['original']['operation']
        payload={'resourceRef':state['targetRef'],
            'journalRef':{'id':self._resource.binding.entity_id,'ownerHubId':self._resource.binding.hub_id,
                          'revision':snapshot.sequence},
            'claimRef':self._journal._ref(group['claim']),
            'originalOperationId':operation['operationId'],'originalPayloadDigest':operation['payloadDigest'],
            'candidateDigest':state['candidateDigest']}
        if observation is not None:payload['observationId']=observation
        admitted=await self._phases.admit(contract,expected_sequence=snapshot.sequence,
            payload=payload,cancellation_ref=operation['cancellationRef'])
        try:
            return await self._journal.advance(admitted.envelope,expected_sequence=snapshot.sequence)
        except ContractError as error:
            if str(error)!='owner_commit_uncertain':raise
            # Replay this exact owner phase, never dispatch a replacement effect.
            return await self._journal.advance(admitted.envelope,expected_sequence=snapshot.sequence)

    async def _group(self, original):
        groups=self._journal._read(await self._journal._ledger.current())
        group=groups.get(original['operationId'])
        if group is None or group['original']['operation']['payloadDigest']!=original['payloadDigest']:
            raise ContractError('board_journal_invalid')
        return group

    async def _settle(self, group, result):
        observation=self._journal._observe(self._journal._ref(group['claim']),result=result)
        await self._phase('federation-board-complete',group,observation=observation)
        return await self._group(group['original']['operation'])

    def _audit_once(self, owner, card, group, kinds, what, *, card_key=None):
        state=group['state']
        key=self._resource.repository_id+'.card.'+(self._resource.card_key if card_key is None else card_key)
        subject=f'$KV.{BUCKET}.{key}'
        detail={'what':what,'kinds':sorted(set(kinds)),'boardClaimId':state['claimId'],
                'originalOperationId':group['original']['operation']['operationId'],
                'originalPayloadDigest':group['original']['operation']['payloadDigest']}
        raw=federation_ledger._j(card).encode()
        decision='redacted' if kinds else 'written'
        with owner.store.tx():
            previous=owner.store.q('SELECT sha,size,decision,detail FROM fed_audit WHERE dir=? AND plane=? '
                'AND rid=? AND subject=? AND json_extract(detail,?)=?',
                ('out','board',self._resource.repository_id,subject,'$.boardClaimId',state['claimId']))
            if previous:
                if (len(previous)!=1 or previous[0]['sha']!=hashlib.sha256(raw).hexdigest()
                        or previous[0]['size']!=len(raw) or previous[0]['decision']!=decision
                        or strict_loads(previous[0]['detail'])!=detail):
                    raise ContractError('board_audit_conflict')
                return
            federation_ledger.audit(owner.store,'out','board','*',self._resource.repository_id,
                subject,card.get('key'),card,decision,detail)

    async def _finish(self, group, card, kinds, what):
        result=group['state']['result']
        if result is None:raise ContractError('board_outcome_uncertain')
        if group['state']['phase']=='finished':return self._receipt(group)
        owner=self._resource._current()
        if result['outcome']=='applied':
            await owner.db(self._audit_once,owner,card,group,kinds,what)
            await owner.db(self._resource.board._operations._mirror,owner,self._resource.repository_id,
                self._resource.card_key,card,result['resourceRef']['revision'])
        result={**result,'auditDone':True,'projectionDone':True}
        group=await self._settle(group,result)
        return self._receipt(group)

    def _receipt(self, group):
        result=group['state']['result']
        if result is None:raise ContractError('board_outcome_uncertain')
        return {'receiptRef':self._journal._ref(group['latest']),
                'resourceRef':result['resourceRef'],'outcome':result['outcome']}

    async def _apply(self, raw, service_request_bytes):
        envelope,_=await self._journal._authorize(raw,ORIGINAL_CONTRACTS,service_request_bytes)
        operation=envelope['operation']
        key=(operation['operationId'],operation['payloadDigest'])
        other=self._originals.get(key)
        if other is not None:
            if not _same_operation(other[0],envelope):
                raise ContractError('owner_operation_conflict')
            result=await asyncio.shield(other[1])
            await self._journal._authorize(raw,ORIGINAL_CONTRACTS,service_request_bytes)
            self._resource._current()
            return result
        task=asyncio.current_task()
        self._originals[key]=(envelope,task)
        try:
            result=await self._execute(raw,service_request_bytes,envelope)
            await self._journal._authorize(raw,ORIGINAL_CONTRACTS,service_request_bytes)
            self._resource._current()
            return result
        finally:
            if self._originals.get(key,(None,None))[1] is task:
                self._originals.pop(key,None)

    async def _execute(self, raw, service_request_bytes, envelope):
        by=self._actor(envelope)
        operation=envelope['operation']
        prior=await self._journal.outcome(operation['operationId'],operation['payloadDigest'])
        if prior is not None:
            group=await self._group(operation)
            if not _same_operation(group['original'],envelope):
                raise ContractError('owner_operation_conflict')
            if group['state']['phase']=='finished':return self._receipt(group)
            return await self._recover(group,raw,service_request_bytes)
        legacy=envelope['contractId']=='federation-board-command'
        change=dict(envelope['payload']['input'] if legacy else envelope['payload']['input']['value'])
        if legacy:
            if change.pop('key',None)!=self._resource.card_key:
                raise ContractError('board_command_target_refused')
        claim=None
        for attempt in range(RETRIES if legacy else 1):
            # Observe the journal BEFORE the card. An intervening qualified
            # writer changes this journal sequence, so preparation cannot commit
            # a stale candidate even if that writer has already finished.
            snapshot=await self._journal._ledger.current()
            kv,entry,card=await self._entry(snapshot)
            base=dict(card);base['_agentmuxOperation']=claim_marker(envelope)
            at=datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
            _validate_board_change(change)
            if not legacy and entry.revision!=operation['expectedVersion']:
                # A real stale-version conflict does not apply the command to
                # a later card or publish metadata merely to obtain a receipt.
                base.update(updated_by=by,updated_at=at)
                candidate=PreparedBoardChange(json.dumps(base).encode(),(),'version conflict')
            else:
                candidate=self._resource.board._operations.prepare_change(self._resource._current(),
                    self._resource.repository_id,base,change,by=by,at=at)
            target=dict(envelope['payload']['resourceRef'])
            if legacy:target['revision']=entry.revision
            try:
                claim=await self._journal.prepare(raw,expected_sequence=snapshot.sequence,
                    candidate=candidate,target_ref=target,observed_sequence=self._resource._sequence,
                    service_request_bytes=service_request_bytes,legacy_attempts=attempt+1 if legacy else None)
                break
            except ContractError as error:
                if not legacy or str(error) not in ('board_journal_busy','owner_revision_conflict') or attempt+1==RETRIES:
                    raise
                await asyncio.sleep(.05*(attempt+1))
        group=await self._group(operation)
        if claim.replayed:
            if group['state']['phase']=='finished':return self._receipt(group)
            raise ContractError('board_outcome_uncertain')
        await self._phase('federation-board-dispatch',group)
        group=await self._group(operation)
        # Phase permission is not the caller's execution permission. Recheck
        # the original wrapper, parents and current grants at this last await.
        if self._allocation_gate is not None:
            await self._allocation_gate.check_card(self._journal._authority,self._resource)
        await self._journal._authorize(raw,ORIGINAL_CONTRACTS,service_request_bytes)
        self._resource._current()
        if not legacy and entry.revision!=operation['expectedVersion']:
            group=await self._settle(group,{'outcome':'conflict','resourceRef':{
                **target,'revision':entry.revision},'auditDone':True,'projectionDone':True})
            return self._receipt(group)
        try:
            revision=await kv.update(entry.key,candidate.value,last=target['revision'])
        except asyncio.CancelledError:
            raise
        except Exception:
            # A timeout or rejected acknowledgment is not proof of rollback.
            # Keep the dispatched claim and exact candidate for reconciliation.
            raise ContractError('board_outcome_uncertain') from None
        if type(revision) is not int or revision<=self._resource._sequence:
            raise ContractError('board_outcome_uncertain')
        group=await self._settle(group,{'outcome':'applied','resourceRef':{**target,'revision':revision},
                                      'auditDone':False,'projectionDone':False})
        return await self._finish(group,candidate.card,candidate.kinds,candidate.what)

    async def _authorize_recovery(self, raw, service_request_bytes, *, query):
        if not query:
            return (await self._journal._authorize(raw,ORIGINAL_CONTRACTS,service_request_bytes))[0]
        if type(raw) is bytes and len(raw) <= 65536 and service_request_bytes is None:
            envelope = strict_loads(raw)
            validate('message-envelope', envelope)
            validate('capability-outcome-query', envelope['payload'])
            decision = await self._journal._authority.evaluate(raw, audience={
                'hubId':self._resource.binding.hub_id,'serviceId':'outcome-owner'})
            if (canonical_bytes(envelope) != raw or envelope['contractId'] != 'capability-outcome-query'
                    or envelope['payload']['input']['contractId'] != 'federation-board-command'
                    or decision.outcome != 'allowed' or canonical_bytes(envelope['operation']['scope']) != self._resource.binding.scope
                    or envelope['payload']['resourceRef']['id'] != self._resource.binding.entity_id
                    or envelope['payload']['resourceRef']['ownerHubId'] != self._resource.binding.hub_id):
                raise ContractError('board_recovery_access_refused')
            self._resource._current()
            return envelope
        if (type(raw) is not bytes or len(raw)>65536 or type(service_request_bytes) is not bytes
                or len(service_request_bytes)>98304):
            raise ContractError('board_recovery_access_refused')
        envelope=strict_loads(raw)
        wrapper=strict_loads(service_request_bytes)
        validate('message-envelope',envelope)
        if (canonical_bytes(envelope)!=raw or canonical_bytes(wrapper)!=service_request_bytes
                or envelope['contractId']!='capability-outcome-query'
                or base64.b64decode(wrapper['claims']['envelopeBytes'],validate=True)!=raw):
            raise ContractError('board_recovery_access_refused')
        decision=evaluate_capability_service_request(await self._journal._authority.current(),service_request_bytes,
            service_id='outcome-owner',now=datetime.now(timezone.utc))
        if (decision.outcome!='allowed' or canonical_bytes(envelope['operation']['scope'])!=self._resource.binding.scope
                or envelope['payload']['resourceRef']['id']!=self._resource.binding.entity_id
                or envelope['payload']['resourceRef']['ownerHubId']!=self._resource.binding.hub_id
                or envelope['payload']['input']['contractId']!='capability-storage-write'):
            raise ContractError('board_recovery_access_refused')
        return envelope

    async def recover(self, raw, *, service_request_bytes):
        if self._closed or len(self._workers)>=32:
            raise ContractError('board_owner_unavailable')
        worker=asyncio.create_task(self._recover_query(raw,service_request_bytes))
        self._workers.add(worker)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _recover_query(self, raw, service_request_bytes):
        envelope=await self._authorize_recovery(raw,service_request_bytes,query=True)
        original=envelope['payload']['input']
        outcome=await self._journal.outcome(original['operationId'],original['payloadDigest'])
        if outcome is None:
            await self._authorize_recovery(raw,service_request_bytes,query=True)
            self._resource._current()
            return None
        group=await self._group(original)
        retained=group['original']
        if (retained['contractId']!=envelope['payload']['input']['contractId']
                or retained['operation']['caller']['authenticatedIdentityRef']!=envelope['operation']['caller']['authenticatedIdentityRef']
                or retained['operation']['effectiveActorRef']!=envelope['operation']['effectiveActorRef']):
            raise ContractError('board_recovery_access_refused')
        other=self._originals.get((original['operationId'],original['payloadDigest']))
        if other is not None:
            try:
                result=await asyncio.shield(other[1])
            except ContractError:
                pass
            else:
                await self._authorize_recovery(raw,service_request_bytes,query=True)
                self._resource._current()
                return result
        result=await self._recover(await self._group(original),raw,service_request_bytes,query=True)
        await self._authorize_recovery(raw,service_request_bytes,query=True)
        self._resource._current()
        return result

    async def legacy_result(self, raw, *, query=False):
        """Return the original retained legacy value, never a later card read."""
        receipt = (await self.recover(raw, service_request_bytes=None) if query else await self.apply(raw))
        envelope = await self._authorize_recovery(raw, None, query=query)
        if receipt is None:
            return None
        original = envelope['payload']['input'] if query else envelope['operation']
        group = await self._group(original)
        state = group['state']
        if (group['original']['contractId'] != 'federation-board-command'
                or state['format'] != 'amx-board-operation-v2' or state['phase'] != 'finished'
                or receipt['outcome'] != 'applied'):
            raise ContractError('board_legacy_result_unavailable')
        card = strict_loads(base64.b64decode(state['candidateBytes'], validate=True))
        card.pop('_agentmuxOperation', None)
        card.pop('_agentmuxRecoveryFence', None)
        return {**card,'rev':receipt['resourceRef']['revision'],'attempts':state['legacyAttempts']}

    async def reconcile(self, raw, *, service_request_bytes):
        """Return the registered storage outcome shape after actual recovery.

        Pending work raises a fixed refusal rather than reporting false absence.
        The host still owns transport signing and the qualified publisher route.
        """
        receipt=await self.recover(raw,service_request_bytes=service_request_bytes)
        original=strict_loads(raw)['payload']['input']
        result={'operationId':original['operationId'],'payloadDigest':original['payloadDigest'],
                'contractId':'capability-storage-write','recordRef':None,'resourceRef':None,'outcome':'absent'}
        if receipt is not None:
            result.update(recordRef=receipt['receiptRef'],resourceRef=receipt['resourceRef'],
                          outcome='committed' if receipt['outcome']=='applied' else 'rejected')
        validate('capability-outcome-query-reply',result)
        return result

    async def _uncertain(self, group):
        if group['state']['phase']!='uncertain' and group['state']['result'] is None:
            await self._settle(group,None)
        raise ContractError('board_outcome_uncertain')

    async def _recover(self, group, raw, service_request_bytes, *, query=False):
        await self._authorize_recovery(raw,service_request_bytes,query=query)
        original=group['original']['operation']
        group=await self._group(original)
        state=group['state']
        if state['phase']=='finished':return self._receipt(group)
        if state['phase']=='prepared':
            # This fresh journal CAS also fences a still-unacknowledged old
            # dispatch claim. A losing phase CAS cannot publish a card effect.
            await self._phase('federation-board-dispatch',group)
            group=await self._group(original);state=group['state']
        snapshot=await self._journal._ledger.current()
        try:
            kv,entry,card=await self._entry(snapshot)
        except Exception:
            return await self._uncertain(group)
        audit=state['preparationAudit']
        if state['result'] is not None:
            if (entry.revision!=state['result']['resourceRef']['revision']
                    or card.get('_agentmuxOperation')!=claim_marker(group['original'])
                    or candidate_digest(entry.value)!=state['candidateDigest']):
                raise ContractError('board_outcome_uncertain')
            return await self._finish(group,card,audit['kinds'],audit['what'])
        for observation in range(2):
            if (card.get('_agentmuxOperation')==claim_marker(group['original'])
                    and candidate_digest(entry.value)==state['candidateDigest']):
                group=await self._settle(group,{'outcome':'applied','resourceRef':{
                    **state['targetRef'],'revision':entry.revision},'auditDone':False,'projectionDone':False})
                return await self._finish(group,card,audit['kinds'],audit['what'])
            fence={'claimId':state['claimId'],'operationId':original['operationId'],
                   'payloadDigest':original['payloadDigest'],'expectedRevision':state['targetRef']['revision']}
            if card.get('_agentmuxRecoveryFence')==fence:
                group=await self._settle(group,{'outcome':'rejected','resourceRef':{
                    **state['targetRef'],'revision':entry.revision},'auditDone':True,'projectionDone':True})
                return self._receipt(group)
            if entry.revision!=state['targetRef']['revision']:
                # The qualified all-writer claim prevents any legitimate writer
                # from overwriting an unresolved operation marker. A different
                # revision without that marker excludes the original exact CAS.
                group=await self._settle(group,{'outcome':'conflict','resourceRef':{
                    **state['targetRef'],'revision':entry.revision},'auditDone':True,'projectionDone':True})
                return self._receipt(group)
            if observation:
                return await self._uncertain(group)
            await self._authorize_recovery(raw,service_request_bytes,query=query)
            self._resource._current()
            value=json.dumps({**card,'_agentmuxRecoveryFence':fence}).encode()
            if len(value)>45000:
                return await self._uncertain(group)
            try:
                revision=await kv.update(entry.key,value,last=state['targetRef']['revision'])
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            else:
                if type(revision) is not int or revision<=self._resource._sequence:
                    return await self._uncertain(group)
                group=await self._settle(group,{'outcome':'rejected','resourceRef':{
                    **state['targetRef'],'revision':revision},'auditDone':True,'projectionDone':True})
                return self._receipt(group)
            # Inspect the single recovery fence attempt. Never repeat the
            # business command, and do not issue a second speculative fence.
            try:
                kv,entry,card=await self._entry(await self._journal._ledger.current())
            except Exception:
                return await self._uncertain(group)
        return await self._uncertain(group)
