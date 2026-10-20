"""Admit one original run for one selected approved plan and attempt."""
import asyncio
from datetime import datetime
import fcntl
import os
import re
import secrets

from nats.js.errors import NotFoundError
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from native_security.secret_custody import _admit, _open_root, _open_namespace, _read_file
from native_security.descriptor_admission import DescriptorPurpose
from state_owner.checkpoints import _publish
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention, RECORD_CHARGE
from execution_owner.plans import ExecutionPlanOwner


def fail(code='capability_process_unavailable'):
    raise ContractError(code) from None


def business(envelope):
    """Delivery signatures may change; the complete operation and payload may not."""
    return {'contractId':envelope['contractId'],'operation':envelope['operation'],
        'payload':envelope['payload'],'destinationHubId':envelope['destinationHubId'],
        'destinationServiceId':envelope['destinationServiceId']}


class _RunInventory:
    def __init__(self,root,namespace,pin):
        self._root=root;self._fd=self._namespace=self._lock=None
        try:
            self._fd=_open_root(root);self._identity=os.fstat(self._fd)
            self._namespace=_open_namespace(self._fd,'process-'+namespace,create=True)
            self._lock=os.open('owner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self._namespace)
            _admit(self._lock,DescriptorPurpose.PRIVATE_FILE)
            fcntl.flock(self._lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.match('policy.json',pin)
            self._pin=pin
        except BaseException:
            self.close()
            raise

    def check(self):
        if self._fd is None:fail()
        _admit(self._fd,DescriptorPurpose.PRIVATE_DIRECTORY)
        current=_open_root(self._root)
        try:
            before,after=self._identity,os.fstat(current)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):fail()
            child=_open_namespace(current,'process-'+self._pin['namespace'],create=False)
            try:
                old,new=os.fstat(self._namespace),os.fstat(child)
                if (old.st_dev,old.st_ino)!=(new.st_dev,new.st_ino):fail()
                held=os.fstat(self._lock)
                named=os.open('owner.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=child)
                try:
                    _admit(self._lock,DescriptorPurpose.PRIVATE_FILE)
                    _admit(named,DescriptorPurpose.PRIVATE_FILE)
                    current_lock=os.fstat(named)
                    if (held.st_dev,held.st_ino)!=(current_lock.st_dev,current_lock.st_ino):fail()
                finally:os.close(named)
            finally:os.close(child)
        finally:os.close(current)
        if self.read('policy.json')!=self._pin:fail()

    def read(self,name):
        try:raw=_read_file(self._namespace,name)
        except FileNotFoundError:return None
        value=strict_loads(raw)
        if len(raw)>65536 or canonical_bytes(value)!=raw:fail()
        return value

    def match(self,name,value):
        existing=self.read(name)
        if existing is None:
            try:_publish(self._namespace,name,canonical_bytes(value),admit=lambda fd:_admit(fd,DescriptorPurpose.PRIVATE_FILE))
            except FileExistsError:pass
            existing=self.read(name)
        if existing!=value:fail('capability_outcome_conflict')
        return value

    def close(self):
        for name in ('_lock','_namespace','_fd'):
            descriptor=getattr(self,name)
            if descriptor is not None:
                os.close(descriptor);setattr(self,name,None)

    def floor(self,sequence=None):
        self.check();values=[]
        for name in os.listdir(self._namespace):
            if not name.startswith('floor-'):continue
            if re.fullmatch(r'floor-[0-9]{16}',name) is None:fail()
            value=self.read(name)
            if value!={'sequence':int(name[6:])}:fail()
            values.append(value['sequence'])
        current=max(values,default=0)
        if sequence is not None:
            if type(sequence) is not int or not current<=sequence<=self._pin['retention']['maxBytes']//RECORD_CHARGE:fail()
            if sequence>current:self.match('floor-%016d'%sequence,{'sequence':sequence})
            return sequence
        return current


class _PinnedRunLedger(OwnerLedger):
    """Persist observed source progress before another owner effect can proceed."""
    async def current(self):
        result=await super().current()
        self._inventory.floor(result.sequence)
        return result

    async def append(self,*args,**kwargs):
        result=await super().append(*args,**kwargs)
        self._inventory.floor(result.sequence)
        return result


class ProcessRunAdmission:
    """A fixed plan admits one deterministic original, never a general allocator.

    The production host supplies its selected broker and private inventory. A
    pre-enrolled OwnerLedger can instead be supplied by a host which already owns
    that exact run; request data cannot select either source.
    """
    def __init__(self,plans,adapter,credentials,signer,*,ledger=None,jetstream=None,
                 stream=None,retention=None,inventory_root=None,namespace=None):
        from execution_owner.container import TaskContainerAdapter
        from execution_owner.task_credentials import TaskCredentialOwner
        from execution_owner.retained import ExecutionServiceSigner
        if (type(plans) is not ExecutionPlanOwner or type(adapter) is not TaskContainerAdapter
                or adapter._plans is not plans or type(credentials) is not TaskCredentialOwner
                or credentials._adapter is not adapter or type(signer) is not ExecutionServiceSigner
                or signer._ingress._reader is not plans._authority):fail()
        self._plans,self._adapter,self._credentials,self._signer=plans,adapter,credentials,signer
        self._owner=None;self._gate=asyncio.Lock();self._closed=False
        self._host=None
        self._ledger=ledger;self._js=jetstream;self._stream=stream;self._retention=retention;self._inventory=None
        if ledger is not None:
            if not isinstance(ledger,OwnerLedger) or any(v is not None for v in (jetstream,stream,retention,inventory_root,namespace)):fail()
        else:
            from nats.js.client import JetStreamContext
            if (type(jetstream) is not JetStreamContext or type(retention) is not Retention
                    or type(namespace) is not str or re.fullmatch('[a-z][a-z0-9_-]{0,63}',namespace) is None
                    or type(stream) is not str or stream!='AMX_PROCESS_'+namespace.upper()):fail()
            pin={'namespace':namespace,'stream':stream,'scope':strict_loads(plans._ledger._binding.scope),
                'executorRef':strict_loads(plans._executor),'profileDigest':payload_digest(strict_loads(plans._profile)),
                'retention':{'maxBytes':retention.max_bytes,'reserveBytes':retention.reserve_bytes,'replicas':retention.replicas}}
            self._inventory=_RunInventory(inventory_root,namespace,pin)

    def __repr__(self):return '<ProcessRunAdmission private>'

    def _new_owner(self):
        from execution_owner.retained import RetainedExecutionOwner
        return RetainedExecutionOwner(self._plans._authority,self._ledger,self._plans,
            self._adapter,self._credentials,self._signer)

    def current(self):
        if self._closed:fail()
        if self._host is not None:
            from .process_host import ProcessHost
            if type(self._host) is not ProcessHost or self._host._admission is not self:fail()
            self._host._open()
        if self._inventory is not None:self._inventory.check()

    async def existing(self):
        self.current()
        async with self._gate:
            if self._owner is not None:
                snapshot=await self._ledger.current()
                return None if snapshot.latest is None else self._owner
            if self._ledger is None:
                assignment=self._inventory.read('assignment.json')
                if assignment is None:return None
                await self._open_ledger(assignment,create=True)
            snapshot=await self._ledger.current()
            if snapshot.latest is None:return None
            self._owner=self._new_owner()
            self._owner._history(snapshot)
            return self._owner

    async def open(self,raw,*,task_inspection,native_evidence):
        self.current()
        async with self._gate:
            if self._owner is not None:
                snapshot=await self._ledger.current()
                if snapshot.latest is not None:
                    state=self._owner._history(snapshot)
                    if business(state['originalEnvelope'])!=business(strict_loads(raw)):fail('capability_outcome_conflict')
                    return self._owner
            admission=await self._plans.admit_start(raw,task_inspection=task_inspection,native_evidence=native_evidence)
            binding=strict_loads(admission.binding)
            # Provisioning reserves only this business request/run. D's first
            # durable record owns the original signed delivery and finite ceiling.
            assignment={'runRef':binding['runRef'],'business':business(strict_loads(raw))}
            if self._inventory is not None:
                self._inventory.check()
                old=self._inventory.read('assignment.json')
                if old is not None:
                    if old!=assignment:fail('capability_outcome_conflict')
                    assignment=old
                if self._ledger is None:await self._open_ledger(assignment,create=True)
            if (self._ledger._binding.entity_id!=binding['runRef']['id']
                    or self._ledger._binding.scope!=self._plans._ledger._binding.scope):fail()
            self._owner=self._new_owner()
            return self._owner

    async def _open_ledger(self,assignment,*,create):
        run=assignment['runRef']
        binding=OwnerBinding(run['ownerHubId'],'execution',run['id'],'attempt',self._plans._ledger._binding.scope)
        inventory=self._inventory;source=inventory.read('source.json');reservation=inventory.read('reservation.json')
        if reservation is None:
            if not create:fail()
            try:await self._js.stream_info(self._stream)
            except NotFoundError:pass
            else:fail('capability_process_unenrolled_stream')
            inventory.match('assignment.json',assignment)
            reservation=inventory.match('reservation.json',{'token':secrets.token_hex(32)})
        try:info=await self._js.stream_info(self._stream)
        except NotFoundError:
            if not create or source is not None:fail()
            config=self._retention.stream_config(stream=self._stream,subject=owner_subject(binding))
            config.metadata={'agentmuxProcessRun':reservation['token']}
            try:info=await self._js.add_stream(config)
            except Exception:info=await self._js.stream_info(self._stream)
        self._retention.validate(info,stream=self._stream,subject=owner_subject(binding))
        if info.config.metadata!={'agentmuxProcessRun':reservation['token']}:fail()
        pin={'created':info.created.isoformat(),'token':reservation['token']}
        if source is None:
            if info.state.last_seq!=0:fail()
            inventory.match('source.json',pin)
        elif source!=pin:fail()
        floor=inventory.floor()
        if info.state.last_seq<floor:fail()
        self._ledger=_PinnedRunLedger(self._js,stream=self._stream,subject=owner_subject(binding),binding=binding,
            retention=self._retention,stream_identity=StreamIdentity(datetime.fromisoformat(pin['created']),floor),
            require_completion_budget=True)
        self._ledger._inventory=inventory

    async def close(self):
        self._closed=True
        if self._owner is not None:await self._owner.close()
        else:
            await self._credentials.close();await self._adapter.checkpoint()
        if self._inventory is not None:self._inventory.close()
