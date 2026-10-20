"""Private namespace gates use actual retained native enrollment and signatures."""
import base64
import copy
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref, NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED, record
from . import test_reply_service as reply_tests
from .private_storage import PrivateStorageResource, private_storage_binding_digest
from .test_storage_contract import StorageWriteContract


class PrivateBindingDigestTests(unittest.TestCase):
    def test_persistent_enrollment_has_stable_known_digest(self):
        from state_owner.retention import Retention
        scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None}
        binding=OwnerBinding('hub-one','plugin-private','task-one','plugin-storage',canonical_bytes(scope))
        digest=private_storage_binding_digest(binding=binding,plugin_identity_ref=ref('plugin'),
            instance_id='plugin-one',package_id='test-plugin',stream='OWNER',
            stream_identity=StreamIdentity(CREATED,0),retention=Retention(67108864,4194304))
        self.assertEqual(digest,'sha256:a2f35bc1c190aeb705a0acf97eeab6b0f98dc09f60bfc14cdfb5056a9f262805')


class PrivateNamespaceTests(reply_tests.StorageReadContract, unittest.IsolatedAsyncioTestCase):
    request=reply_tests.ReplyServiceTests.request
    enroll=reply_tests.ReplyServiceTests.enroll
    signed=reply_tests.ReplyServiceTests.signed
    call=reply_tests.ReplyServiceTests.call
    verify=reply_tests.ReplyServiceTests.verify

    def setUp(self):
        reply_tests.ReplyServiceTests.setUp(self)
        patch('capability_owner.private_storage.datetime',_Clock).start()
        self.row['facts']['grant']['actions']=['read','write','inspect']
        base=next(g for g in self.record['state']['grants'] if g['ref']['id']=='capability')
        for suffix,contract,action,resource_class in (
                ('write','capability-storage-write','write','storage'),
                ('outcome','capability-outcome-query','inspect','outcome')):
            grant=copy.deepcopy(base)
            grant.update(ref=ref('private-'+suffix),contractId=contract)
            self.record['state']['grants'].append(grant)
            self.row['facts']['domainBindings'].append({'id':'private-'+suffix,'contractId':contract,
                'action':action,'resourceClass':resource_class,'resourceIds':['task-one']})
            self.row['facts']['policy']['decisions'].append({'access':{'action':action,
                'resourceClass':resource_class,'resourceId':'task-one'},'outcome':'allow'})
        binding=OwnerBinding('hub-one','plugin-private','task-one','plugin-storage',
            canonical_bytes(self.row['facts']['grant']['scope']))
        self.row['privateStorageResources']=[{'resourceId':'task-one',
            'scope':copy.deepcopy(self.row['facts']['grant']['scope']),
            'bindingDigest':private_storage_binding_digest(binding=binding,plugin_identity_ref=ref('plugin'),
                instance_id='plugin-one',package_id='test-plugin',stream='OWNER',
                stream_identity=StreamIdentity(CREATED,0),retention=self.policy)}]
        self.js.messages[0].data=canonical_bytes(self.record)

    async def asyncSetUp(self):
        await reply_tests.ReplyServiceTests.asyncSetUp(self)
        self.namespace_js=FakeJetStream(self.policy)
        self.binding=OwnerBinding('hub-one','plugin-private','task-one','plugin-storage',
            canonical_bytes(self.row['facts']['grant']['scope']))
        self.namespace_js.config=self.policy.stream_config(stream='OWNER',subject=owner_subject(self.binding))
        self.resource=self.open()
        self.reply_service._receiver._resources['task-one']=self.resource

    def open(self, **changes):
        args=dict(binding=self.binding,stream='OWNER',stream_identity=StreamIdentity(CREATED,0),
            retention=self.policy,plugin_identity_ref=ref('plugin'),instance_id='plugin-one',package_id='test-plugin')
        args.update(changes)
        return PrivateStorageResource.open_existing(self.namespace_js,**args)

    async def test_unsupported_retention_is_refused_before_history_can_become_unreadable(self):
        from state_owner.retention import Retention
        with self.assertRaisesRegex(ContractError,'^owner_history_capacity$'):
            self.open(retention=Retention(1024*1024*1024,4*1024*1024))
        self.assertEqual(self.namespace_js.messages,[])

    async def test_reference_retention_fits_strict_reader_and_completion_budget(self):
        from state_owner.retention import Retention
        resource=self.open(retention=Retention(64*1024*1024,4*1024*1024))
        self.assertTrue(resource.ledger.completion_budget_required)

    async def test_direct_resource_cannot_bypass_strict_ledger_composition(self):
        from state_owner.ledger import OwnerLedger
        ledger=OwnerLedger(self.namespace_js,stream='OWNER',subject=owner_subject(self.binding),
            binding=self.binding,stream_identity=StreamIdentity(CREATED,0),retention=self.policy)
        with self.assertRaisesRegex(ContractError,'^capability_owner_configuration$'):
            PrivateStorageResource(self.binding,ledger,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')

    async def replace_mapping(self, entries):
        row=copy.deepcopy(self.row)
        previous=copy.deepcopy(row['ref']);row['ref']['revision']+=1
        row['privateStorageResources']=entries
        self.claims.update(operationId='replace-mapping-'+str(row['ref']['revision']),
            contractId='identity-native-instance-set',grantRef=ref('native-admin'),
            expectedVersion=len(self.js.messages),payload={
                'authorityId':'authority-one','record':row,'previousRef':previous})
        result=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')
        self.row=row

    async def test_matching_namespace_checks_full_signed_native_wrapper(self):
        decision=await self.resource.authorize(self.service.reader,self.inner,self.signed())
        self.assertEqual(decision.outcome,'allowed')
        self.assertEqual(self.namespace_js.messages,[])
        self.assertNotIn('plugin-one',repr(self.resource))

    async def test_absent_or_changed_enrollment_refuses_previously_signed_request(self):
        raw=self.signed()
        for entries in ([],[{**self.row['privateStorageResources'][0],
                             'bindingDigest':'sha256:'+'0'*64}]):
            await self.replace_mapping(entries)
            with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await self.resource.authorize(self.service.reader,self.inner,raw)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_final_reply_rechecks_current_namespace_enrollment(self):
        await self.seed()
        admit=self.reply_service._admit
        calls=0
        async def changed(request, reply_subject):
            nonlocal calls
            calls+=1
            if calls==2:
                await self.replace_mapping([])
            return await admit(request,reply_subject)
        with patch.object(self.reply_service,'_admit',side_effect=changed):
            with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()
        self.assertEqual(calls,2)
        self.assertEqual(len(self.namespace_js.messages),1)

    async def test_digest_binds_retention_and_broker_domain_before_access(self):
        from state_owner.retention import Retention
        alternate=self.open(retention=Retention(64*1024*1024,4*1024*1024))
        self.assertNotEqual(alternate.binding_digest,self.resource.binding_digest)
        with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
            await alternate.authorize(self.service.reader,self.inner,self.signed())
        self.namespace_js._prefix='$JS.other.API'
        with self.assertRaisesRegex(ContractError,'^capability_owner_configuration$'):
            self.open()
        self.assertNotEqual(self.open(domain='other').binding_digest,self.resource.binding_digest)
        with self.assertRaisesRegex(ContractError,'^capability_owner_configuration$'):
            self.open(domain=42)

    async def test_resource_grant_does_not_cross_identity_installation_or_package(self):
        for changed in ({'plugin_identity_ref':ref('alice')},{'instance_id':'other-installation'},
                        {'package_id':'other-package'}):
            resource=self.open(**changed)
            with self.subTest(changed=tuple(changed)),self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
                await resource.authorize(self.service.reader,self.inner,self.signed())
        self.assertEqual(self.namespace_js.messages,[])

    async def test_resource_grant_does_not_cross_project_scope(self):
        scope={**self.row['facts']['grant']['scope'],'projectId':'other-project'}
        binding=OwnerBinding('hub-one','plugin-private','task-one','plugin-storage',canonical_bytes(scope))
        resource=self.open(binding=binding)
        with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
            await resource.authorize(self.service.reader,self.inner,self.signed())

    async def test_signed_wrapper_cannot_be_detached_from_inner_bytes(self):
        changed=self.inner+b' '
        with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
            await self.resource.authorize(self.service.reader,changed,self.signed())

    async def test_direct_inner_receiver_call_cannot_bypass_namespace_gate(self):
        with self.assertRaisesRegex(ContractError,'^capability_access_refused$'):
            await self.reply_service._receiver.handle(self.inner)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_current_revocation_refuses_previously_signed_namespace_request(self):
        raw=self.signed()
        self.claims.update(operationId='revoke-private-access',contractId='identity-revoke',grantRef=ref('grant'),
            expectedVersion=2,payload={'authorityId':'authority-one','targetRef':ref('host-transport')})
        result=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')
        with self.assertRaises(ContractError):
            await self.resource.authorize(self.service.reader,self.inner,raw)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_unwritten_namespace_read_does_not_provision_or_invent_a_value(self):
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):
            await self.resource.read(0)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_signed_service_rechecks_private_namespace_association(self):
        self.reply_service._receiver._resources['task-one']=self.open(instance_id='other-installation')
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call()
        self.assertEqual(self.namespace_js.messages,[])


    async def contract_seed(self):
        original=await self.seed()
        return canonical_bytes(original['state']['value'])

    async def seed(self, value=None, owner_changes=None):
        original=record(operation='private-original')
        original.update(ownerDomain='plugin-private',entityKind='plugin-storage',effects=[])
        original['operation']['scope']=copy.deepcopy(self.row['facts']['grant']['scope'])
        owner={'pluginIdentityRef':ref('plugin'),'instanceId':'plugin-one','packageId':'test-plugin'}
        owner.update(owner_changes or {})
        original['state']={'formatVersion':1,'owner':owner,'value':value if value is not None else {'theme':'dark'}}
        original['authorizationDecision']={'operationId':original['operation']['operationId'],
            'decision':'allowed','reason':'current_authority','actorRef':original['operation']['effectiveActorRef'],
            'contractId':'capability-storage-write'}
        await self.resource.ledger.append(original,expected_sequence=0,completion_records=0)
        return original

    async def test_retained_private_document_read_through_actual_signed_service(self):
        original=await self.seed({'settings':{'theme':'dark'},'unknownFutureField':[None,42]})
        raw=await self.call()
        payload=strict_loads(self.verify(raw))
        self.assertEqual(strict_loads(base64.b64decode(payload['data'])),original['state']['value'])
        self.assertEqual(len(self.namespace_js.messages),1)
        self.assertNotIn('pluginIdentityRef',base64.b64decode(payload['data']).decode())

    async def test_stored_namespace_owner_mismatch_refuses_private_read(self):
        for changes in ({'pluginIdentityRef':ref('other-plugin')},
                        {'pluginIdentityRef':{**ref('plugin'),'revision':True}},
                        {'instanceId':'other-installation'},{'packageId':'other-package'}):
            self.namespace_js.messages.clear()
            self.resource=self.open()
            self.reply_service._receiver._resources['task-one']=self.resource
            await self.seed(owner_changes=changes)
            with self.subTest(changes=tuple(changes)),self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()

    async def test_unknown_private_format_and_oversized_document_refuse(self):
        original=await self.seed()
        for changes in ({'formatVersion':2},{'value':'x'*16385},{'extra':'unrecognized'}):
            changed=copy.deepcopy(original)
            changed['state'].update(changes)
            self.namespace_js.messages[0].data=canonical_bytes(changed)
            with self.subTest(changes=tuple(changes)),self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()

    async def test_restarted_namespace_keeps_value_and_exact_original_operation(self):
        original=await self.seed({'persistent':True})
        restarted=self.open()
        self.assertEqual(restarted.binding_digest,self.resource.binding_digest)
        self.assertEqual(strict_loads(await restarted.read(1)),{'persistent':True})
        result=await restarted.ledger.outcome(original['operation']['operationId'],original['operation']['payloadDigest'])
        self.assertEqual(strict_loads(result.record),original)
        self.assertEqual(len(self.namespace_js.messages),1)


    async def test_private_outcome_checks_stored_namespace_owner_too(self):
        original=await self.seed()
        self.claims.update(operationId='private-query',contractId='capability-outcome-query',
            grantRef=ref('private-outcome'),expectedVersion=1,payload={'resourceRef':ref('task-one'),
                'input':{'operationId':original['operation']['operationId'],
                         'payloadDigest':original['operation']['payloadDigest'],
                         'contractId':'capability-storage-write'}})
        admitted=await self.service.ingress.admit(self.request(),cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        self.wrapper.update(requestId=strict_loads(admitted.envelope)['correlationId'],
            operationId='private-query',serviceId='outcome-owner',requestContractId='capability-outcome-query',
            replyContractId='capability-outcome-query-reply',envelopeBytes=base64.b64encode(admitted.envelope).decode())
        response=await self.reply_service._receiver.handle(admitted.envelope,service_request_bytes=self.signed())
        self.assertEqual(strict_loads(response.payload)['outcome'],'committed')
        original['state']['owner']['instanceId']='other-installation'
        self.namespace_js.messages[0].data=canonical_bytes(original)
        with self.assertRaisesRegex(ContractError,'^capability_resource_stale$'):
            await self.reply_service._receiver.handle(admitted.envelope,service_request_bytes=self.signed())


class PrivateWriteTests(StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    request=PrivateNamespaceTests.request
    enroll=PrivateNamespaceTests.enroll
    signed=PrivateNamespaceTests.signed
    call=PrivateNamespaceTests.call
    verify=PrivateNamespaceTests.verify
    open=PrivateNamespaceTests.open
    replace_mapping=PrivateNamespaceTests.replace_mapping
    asyncSetUp=PrivateNamespaceTests.asyncSetUp

    def setUp(self):
        PrivateNamespaceTests.setUp(self)
        patch('state_owner.ledger.datetime',_Clock).start()

    async def contract_prepare(self,operation,revision=0):
        return await self.prepare(operation=operation,revision=revision,value={'value':operation})

    async def contract_dispatch(self,raw):
        return strict_loads(self.verify(await self.call(raw),raw))

    async def contract_outcome(self,inner):
        return await self.outcome(inner)

    async def prepare(self, operation='private-write', revision=0, value=None, *, query=None):
        contract='capability-storage-write' if query is None else 'capability-outcome-query'
        inputs={'value':value} if query is None else query
        self.claims.update(operationId=operation,contractId=contract,
            grantRef=ref('private-write' if query is None else 'private-outcome'),
            expectedVersion=revision,payload={'resourceRef':{**ref('task-one'),'revision':revision},'input':inputs})
        admitted=await self.service.ingress.admit(self.request(),cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        self.wrapper.update(requestId=strict_loads(admitted.envelope)['correlationId'],operationId=operation,
            serviceId='storage-owner' if query is None else 'outcome-owner',requestContractId=contract,
            replyContractId='capability-storage-write-reply' if query is None else 'capability-outcome-query-reply',
            resourceRef={**ref('task-one'),'revision':revision},envelopeBytes=base64.b64encode(admitted.envelope).decode())
        return self.signed(),admitted.envelope

    async def outcome(self, inner, *, now=None):
        from .reply_service import CapabilityReplyService
        original=strict_loads(inner)['operation']
        raw,_=await self.prepare(operation='query-'+original['operationId'],revision=0,query={
            'operationId':original['operationId'],'payloadDigest':original['payloadDigest'],
            'contractId':'capability-storage-write'})
        responder=self.outcome_responder()
        response=await responder.handle(raw,received_reply_subject=self.wrapper['replySubject'])
        return strict_loads(self.verify(response,raw,**({} if now is None else {'now':now})))

    def outcome_responder(self):
        from .reply_service import CapabilityReplyService
        responder=CapabilityReplyService(self.service.reader,resources=[self.resource],hub_id='hub-one',
            profile_id='profile-one',authority_id='authority-one',service_id='outcome-owner',
            service_identity_ref=ref('service'),service_instance_id='ingress-one',signing_key_ref=ref('issuer'),
            signing_seed=reply_tests.SEED,request_signing_key_ref=ref('issuer'))
        self.addAsyncCleanup(responder.close)
        return responder

    async def test_exact_version_write_returns_real_retained_receipt_and_value(self):
        raw,inner=await self.prepare(value={'nested':[None,True,42],'unknownFutureField':'kept'})
        response=await self.call(raw)
        receipt=strict_loads(self.verify(response,raw))
        self.assertEqual(receipt['outcome'],'applied')
        self.assertEqual(receipt['receiptRef']['revision'],1)
        self.assertEqual(receipt['resourceRef'],{**ref('task-one'),'revision':1})
        stored=strict_loads(self.namespace_js.messages[0].data)
        self.assertEqual(receipt['receiptRef']['id'],stored['recordId'])
        self.assertEqual(stored['operation'],strict_loads(inner)['operation'])
        self.assertEqual(stored['authorizationDecision']['contractId'],'capability-storage-write')
        self.assertEqual(strict_loads(await self.resource.read(1)),{'nested':[None,True,42],'unknownFutureField':'kept'})
        self.assertEqual(stored['effects'],[])
        self.assertEqual((await self.outcome(inner))['outcome'],'committed')

    async def test_original_replay_after_newer_write_does_not_consume_another_revision(self):
        raw,inner=await self.prepare(operation='first',value={'v':1})
        first=strict_loads(self.verify(await self.call(raw),raw))
        second,_=await self.prepare(operation='second',revision=1,value={'v':2})
        await self.call(second)
        replay=strict_loads(self.verify(await self.call(raw),raw))
        self.assertEqual(replay,first)
        self.assertEqual(len(self.namespace_js.messages),2)
        self.assertEqual(strict_loads(await self.resource.read(2)),{'v':2})

    async def test_changed_content_under_original_operation_refuses(self):
        raw,_=await self.prepare(operation='same-id',value={'v':1})
        await self.call(raw)
        raw,_=await self.prepare(operation='same-id',value={'v':2})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        self.assertEqual(len(self.namespace_js.messages),1)
        self.assertEqual(strict_loads(await self.resource.read(1)),{'v':1})

    async def test_conflict_retains_real_outcome_and_unchanged_value_at_new_namespace_revision(self):
        raw,_=await self.prepare(operation='winner',value={'v':1})
        await self.call(raw)
        original_state=strict_loads(self.namespace_js.messages[0].data)['state']
        stale,inner=await self.prepare(operation='stale',value={'v':2})
        receipt=strict_loads(self.verify(await self.call(stale),stale))
        self.assertEqual(receipt['outcome'],'conflict')
        self.assertEqual(receipt['resourceRef'],{**ref('task-one'),'revision':2})
        self.assertEqual(len(self.namespace_js.messages),2)
        stored=strict_loads(self.namespace_js.messages[1].data)
        self.assertEqual(stored['state'],original_state)
        self.assertEqual(stored['outcome'],'rejected')
        self.assertEqual(receipt['receiptRef']['id'],stored['recordId'])
        self.assertEqual(strict_loads(await self.resource.read(2)),{'v':1})
        recovered=await self.outcome(inner)
        self.assertEqual(recovered['outcome'],'rejected')
        self.assertEqual(recovered['resourceRef'],receipt['resourceRef'])
        latest,_=await self.prepare(operation='later-after-conflict',revision=2,value={'v':3})
        await self.call(latest)
        replay=strict_loads(self.verify(await self.call(stale),stale))
        self.assertEqual(replay,receipt)
        self.assertEqual(len(self.namespace_js.messages),3)

    async def test_lost_ack_reconciles_original_pair_and_replay_is_single_commit(self):
        raw,inner=await self.prepare(value={'persisted':'despite lost reply'})
        self.namespace_js.lose_ack=True
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        self.assertEqual(len(self.namespace_js.messages),1)

        result=await self.outcome(inner)
        self.assertEqual(result['outcome'],'committed')
        replay=strict_loads(self.verify(await self.call(raw),raw))
        self.assertEqual(replay['receiptRef'],result['recordRef'])
        self.assertEqual(len(self.namespace_js.messages),1)

    async def test_indexed_namespace_accepts_same_value_after_conflict(self):
        import tempfile
        from pathlib import Path
        from state_owner.history import OwnerHistory
        from state_owner.ledger import OwnerLedger

        with tempfile.TemporaryDirectory() as directory:
            history = OwnerHistory(Path(directory).resolve() / 'history.sqlite', self.binding,
                stream_identity=StreamIdentity(CREATED, 0))
            try:
                ledger = OwnerLedger(self.namespace_js, stream='OWNER',
                    subject=owner_subject(self.binding), binding=self.binding,
                    stream_identity=StreamIdentity(CREATED, 0), retention=self.policy,
                    history=history, require_completion_budget=True)
                self.resource = PrivateStorageResource(self.binding, ledger,
                    canonical_bytes(ref('plugin')), 'plugin-one', 'test-plugin')
                self.reply_service._receiver._resources['task-one'] = self.resource
                original, _ = await self.prepare(operation='indexed-first', value={'v': 1})
                first = await self.contract_dispatch(original)
                stale, _ = await self.prepare(operation='indexed-stale', value={'v': 2})
                conflict = await self.contract_dispatch(stale)
                self.assertEqual(conflict['outcome'], 'conflict')
                self.assertEqual(strict_loads(await self.resource.read(2)), {'v': 1})
                later, _ = await self.prepare(operation='indexed-later', revision=2, value={'v': 1})
                applied = await self.contract_dispatch(later)
                self.assertEqual(applied['outcome'], 'applied')
                self.assertEqual(applied['resourceRef']['revision'], 3)
                self.assertEqual(strict_loads(await self.resource.read(3)), {'v': 1})
                self.assertEqual(await self.contract_dispatch(original), first)
                self.assertEqual(history.verified_cursor, 3)
                self.assertEqual(len(self.namespace_js.messages), 3)
            finally:
                history.close()

    async def test_current_revocation_after_data_read_prevents_commit(self):
        raw,_=await self.prepare(value={'must':'not commit'})
        actual=self.resource.ledger.current
        revoked=False
        async def current():
            nonlocal revoked
            result=await actual()
            if not revoked:
                revoked=True
                self.claims.update(operationId='revoke-during-private-write',contractId='identity-revoke',
                    grantRef=ref('grant'),expectedVersion=2,
                    payload={'authorityId':'authority-one','targetRef':ref('host-transport')})
                receipt=strict_loads(await self.service.handle(self.request()))
                self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
            return result
        with patch.object(self.resource.ledger,'current',side_effect=current):
            with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call(raw)
        self.assertTrue(revoked)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_capacity_refusal_preserves_value_and_original_replay(self):
        from state_owner.retention import Retention
        retention=Retention(262144,131072)
        self.namespace_js.config=retention.stream_config(stream='OWNER',subject=owner_subject(self.binding))
        self.resource=self.open(retention=retention)
        self.reply_service._receiver._resources['task-one']=self.resource
        await self.replace_mapping([{'resourceId':'task-one','scope':strict_loads(self.binding.scope),
                                    'bindingDigest':self.resource.binding_digest}])
        raw,_=await self.prepare(operation='fits',value={'v':1})
        await self.call(raw)
        full,_=await self.prepare(operation='full',revision=1,value={'v':2})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(full)
        await self.call(raw)
        self.assertEqual(len(self.namespace_js.messages),1)
        self.assertEqual(strict_loads(await self.resource.read(1)),{'v':1})

    async def test_oversized_private_value_never_appends(self):
        raw,_=await self.prepare(value='x'*16385)
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        self.assertEqual(self.namespace_js.messages,[])

    async def test_cancelled_reply_and_close_keep_original_dispatched_write(self):
        import asyncio
        raw,inner=await self.prepare(value={'v':'committed before cancellation'})
        entered,release=asyncio.Event(),asyncio.Event()
        actual=self.namespace_js.publish
        async def publish(*args,**kwargs):
            result=await actual(*args,**kwargs)
            entered.set()
            await release.wait()
            return result
        with patch.object(self.namespace_js,'publish',side_effect=publish):
            task=asyncio.create_task(self.call(raw))
            try:
                await asyncio.wait_for(entered.wait(),2)
                workers=tuple(self.reply_service._receiver._workers)
                self.assertEqual(len(workers),1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
                with self.assertRaisesRegex(ContractError,'^capability_cleanup_incomplete$'):
                    await self.reply_service.close(timeout=0.01)
                self.assertFalse(workers[0].done())
                self.assertEqual(len(self.namespace_js.messages),1)
            finally:
                release.set()
                if not task.done():task.cancel()
                await asyncio.gather(task,return_exceptions=True)
                await self.reply_service.close(timeout=2)
            self.assertTrue(workers[0].done())
            self.assertEqual(len(self.namespace_js.messages),1)
        self.assertEqual((await self.outcome(inner))['outcome'],'committed')


    async def test_same_payload_pair_cannot_substitute_original_operation_metadata(self):
        raw,_=await self.prepare(operation='same-provenance',value={'v':1})
        await self.call(raw)
        self.claims['expiresAt']='2026-10-09T12:00:29Z'
        changed,_=await self.prepare(operation='same-provenance',value={'v':1})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(changed)
        self.assertEqual(len(self.namespace_js.messages),1)

    async def test_competing_exact_version_writes_have_one_commit_without_reapply(self):
        import asyncio
        first,_=await self.prepare(operation='competing-one',value={'winner':1})
        second,_=await self.prepare(operation='competing-two',value={'winner':2})
        results=await asyncio.gather(self.call(first),self.call(second),return_exceptions=True)
        outcomes=[strict_loads(self.verify(result,raw))['outcome'] for result,raw in zip(results,(first,second))]
        self.assertCountEqual(outcomes,['applied','conflict'])
        self.assertEqual(len(self.namespace_js.messages),2)
        self.assertIn(strict_loads(await self.resource.read(2)),({'winner':1},{'winner':2}))

    async def test_append_uses_current_authority_deadline_and_zero_completion_budget(self):
        raw,_=await self.prepare(value={'v':1})
        actual=self.resource.ledger.append
        with patch.object(self.resource.ledger,'append',wraps=actual) as append:
            await self.call(raw)
        self.assertEqual(append.call_args.kwargs['completion_records'],0)
        self.assertEqual(append.call_args.kwargs['valid_until'],
            _Clock.fromisoformat(strict_loads(raw)['claims']['validUntil']))


    async def test_conflict_in_empty_namespace_cannot_invent_an_initial_value(self):
        raw,_=await self.prepare(revision=9,value={'must':'not create value'})
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        self.assertEqual(self.namespace_js.messages,[])


    async def test_expired_write_recovers_original_result_reference_under_fresh_query_authority(self):
        from datetime import timedelta
        from contextlib import ExitStack
        raw,inner=await self.prepare(operation='expired-original',value={'v':1})
        self.namespace_js.lose_ack=True
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        later,_=await self.prepare(operation='newer-value',revision=1,value={'v':2})
        await self.call(later)
        observed=NOW+timedelta(seconds=40)
        class Later(_Clock):
            @classmethod
            def now(cls,tz=None):return observed
        with ExitStack() as stack:
            stack.enter_context(patch('identity.authority._utc_now',return_value=observed))
            for module in ('identity.ingress','capability_owner.reply_service','capability_owner.private_storage'):
                stack.enter_context(patch(module+'.datetime',Later))
            with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call(raw)
            self.claims.update(issuedAt=observed.isoformat().replace('+00:00','Z'),
                expiresAt=(observed+timedelta(seconds=20)).isoformat().replace('+00:00','Z'))
            self.wrapper.update(issuedAt=observed.isoformat().replace('+00:00','Z'),
                validUntil=(observed+timedelta(seconds=4)).isoformat().replace('+00:00','Z'))
            recovered=await self.outcome(inner,now=observed)
        self.assertEqual(recovered['contractId'],'capability-storage-write')
        self.assertEqual(recovered['outcome'],'committed')
        self.assertEqual(recovered['resourceRef'],{**ref('task-one'),'revision':1})
        self.assertNotEqual(recovered['recordRef']['id'],recovered['resourceRef']['id'])
        self.assertEqual(len(self.namespace_js.messages),2)
        self.assertEqual(strict_loads(await self.resource.read(2)),{'v':2})

    async def test_absent_storage_recovery_has_explicit_null_result_reference(self):
        _,inner=await self.prepare(operation='never-dispatched',value={'v':1})
        result=await self.outcome(inner)
        self.assertEqual(result['contractId'],'capability-storage-write')
        self.assertEqual(result['outcome'],'absent')
        self.assertIsNone(result['recordRef'])
        self.assertIsNone(result['resourceRef'])
        self.assertEqual(self.namespace_js.messages,[])


    async def test_storage_recovery_requires_current_original_write_permission(self):
        raw,inner=await self.prepare(operation='original-withdrawn',value={'v':1})
        await self.call(raw)
        operation=strict_loads(inner)['operation']
        query,_=await self.prepare(operation='query-before-revocation',query={
            'operationId':operation['operationId'],'payloadDigest':operation['payloadDigest'],
            'contractId':'capability-storage-write'})
        self.claims.update(operationId='revoke-original-write-permission',contractId='identity-revoke',
            grantRef=ref('grant'),expectedVersion=2,
            payload={'authorityId':'authority-one','targetRef':ref('private-write')})
        result=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')
        responder=self.outcome_responder()
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await responder.handle(query,received_reply_subject=self.wrapper['replySubject'])
        self.assertEqual(len(self.namespace_js.messages),1)


    async def test_storage_recovery_requires_current_native_original_write_binding(self):
        _,inner=await self.prepare(operation='native-original',value={'v':1})
        row=copy.deepcopy(self.row)
        previous=copy.deepcopy(row['ref']);row['ref']['revision']+=1
        row['facts']['domainBindings']=[b for b in row['facts']['domainBindings']
                                      if b['contractId']!='capability-storage-write']
        row['facts']['grant']['actions'].remove('write')
        row['facts']['policy']['decisions']=[d for d in row['facts']['policy']['decisions']
                                           if d['access']['action']!='write']
        self.claims.update(operationId='withdraw-native-write',contractId='identity-native-instance-set',
            grantRef=ref('native-admin'),expectedVersion=2,
            payload={'authorityId':'authority-one','record':row,'previousRef':previous})
        receipt=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
        self.row=row
        original=strict_loads(inner)['operation']
        self.wrapper['nativeFactsDigest']=payload_digest(row['facts'])
        raw,query=await self.prepare(operation='native-original-query',query={
            'operationId':original['operationId'],'payloadDigest':original['payloadDigest'],
            'contractId':'capability-storage-write'})
        with self.assertRaisesRegex(ContractError,'^native_operation_binding$'):
            await self.resource.authorize(self.service.reader,query,raw)
        self.assertEqual(self.namespace_js.messages,[])
