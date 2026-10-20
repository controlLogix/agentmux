"""Actual retained enrollment and signatures; broker transport is controlled offline."""
import asyncio
import base64
import copy
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity import test_native_bridge
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED, record
from .resources import RetainedResource
from .reply_service import CapabilityReplyService, verify_capability_response, REQUEST_LIMIT, _digest


class Subscription:
    def __init__(self):
        self.drains=0
    async def drain(self):
        self.drains+=1


class Connection:
    max_payload=1048576
    def __init__(self):
        self.sent=[]
        self.subscription=Subscription()
        self.subscribed=asyncio.Event()
        self.release=asyncio.Event(); self.release.set()
    async def subscribe(self, subject, **options):
        self.subject,self.options=subject,options
        self.subscribed.set()
        await self.release.wait()
        return self.subscription
    async def flush(self):
        pass
    async def publish(self, subject, data):
        self.sent.append((subject,data))


class StorageReadContract:
    """The same signed read interface for actual domain and private providers."""
    async def test_common_storage_read_preserves_content_and_reference(self):
        expected=await self.contract_seed()
        raw=self.signed()
        response=await self.call(raw)
        payload=strict_loads(self.verify(response,raw))
        self.assertEqual(payload['resourceRef'],self.wrapper['resourceRef'])
        self.assertEqual(base64.b64decode(payload['data']),expected)

    async def test_common_storage_read_refuses_expired_request(self):
        await self.contract_seed()
        self.wrapper['validUntil']=self.wrapper['issuedAt']
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call()

    async def test_common_storage_read_refuses_after_close(self):
        await self.contract_seed()
        await self.reply_service.close()
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call()


class ReplyServiceTests(unittest.IsolatedAsyncioTestCase):
    request=test_native_bridge.NativeBridgeTests.request
    enroll=test_native_bridge.NativeBridgeTests.enroll

    def setUp(self):
        test_native_bridge.NativeBridgeTests.setUp(self)
        patch('identity.authority._utc_now',return_value=NOW).start()
        patch('capability_owner.reply_service.datetime',_Clock).start()
        self.row['facts']['grant']['actions']=['read']
        self.row['facts']['policy']['decisions']=[{'access':{
            'action':'read','resourceClass':'storage','resourceId':'task-one'},'outcome':'allow'}]
        self.row['facts']['domainBindings']=[{'id':'storage-read', 'contractId':'capability-storage-read',
            'action':'read','resourceClass':'storage','resourceIds':['task-one']}]
        base=self.record['state']['grants'][0]
        grant=copy.deepcopy(base); grant.update(ref=ref('capability'),contractId='capability-storage-read',resourceId='task-one')
        self.record['state']['grants'].append(grant)
        host=copy.deepcopy(base); host.update(ref=ref('host-prepare'), callerRef=ref('host'),actorRef=ref('host'),
            contractId='native-authority-prepare-domain-call',resourceId='plugin-one')
        self.record['state']['grants'].append(host)
        self.js.messages[0].data=canonical_bytes(self.record)
        self.connection=Connection()

    async def asyncSetUp(self):
        await self.enroll()
        binding=OwnerBinding('hub-one','task','task-one','task',canonical_bytes(self.row['facts']['grant']['scope']))
        self.data_js=FakeJetStream(self.policy)
        self.data_js.config=self.policy.stream_config(stream='OWNER',subject=owner_subject(binding))
        resource=RetainedResource.open_existing(self.data_js,binding=binding,stream='OWNER',
            stream_identity=StreamIdentity(CREATED,0),retention=self.policy)
        self.original=record()
        self.original['operation']['scope']=copy.deepcopy(self.row['facts']['grant']['scope'])
        await resource.ledger.append(self.original,expected_sequence=0)
        self.reply_service=CapabilityReplyService(self.service.reader,resources=[resource],hub_id='hub-one',
            profile_id='profile-one',authority_id='authority-one',service_id='storage-owner',
            service_identity_ref=ref('service'),service_instance_id='ingress-one',signing_key_ref=ref('issuer'),
            signing_seed=SEED,request_signing_key_ref=ref('issuer'),connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)
        self.claims.update(operationId='capability-read',contractId='capability-storage-read',grantRef=ref('capability'),
            expectedVersion=1,payload={'resourceRef':ref('task-one'),'input':{}})
        admitted=await self.service.ingress.admit(self.request(),cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome,'allowed')
        self.inner=admitted.envelope
        self.wrapper={'purpose':'agentmux-capability-service-request-v1','requestId':strict_loads(self.inner)['correlationId'],
            'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one','owner':self.row['owner'],
            'serviceId':'storage-owner','requestContractId':'capability-storage-read',
            'replyContractId':'capability-content-reply','operationId':'capability-read','resourceRef':ref('task-one'),
            'scope':copy.deepcopy(self.row['facts']['grant']['scope']),'replySubject':'_INBOX.abcdefghijklmnop',
            'issuedAt':NOW.isoformat().replace('+00:00','Z'),
            'validUntil':(NOW+timedelta(seconds=4)).isoformat().replace('+00:00','Z'),
            'signingKeyRef':ref('issuer'),'hostTransportRef':ref('host-transport'),
            'nativeFactsDigest':payload_digest(self.row['facts']),
            'envelopeBytes':base64.b64encode(self.inner).decode()}

    def signed(self):
        return canonical_bytes({'schemaVersion':'1.0.0','algorithm':'Ed25519',
            'canonicalization':'RFC8785-JCS-UTF8','claims':self.wrapper,'signature':sign_claims(self.wrapper,SEED)})

    async def call(self, raw=None, reply=None):
        return await self.reply_service.handle(raw or self.signed(),
            received_reply_subject=reply or self.wrapper['replySubject'])

    def verify(self, response, request=None, **changes):
        args=dict(public_key=self.record['state']['issuers'][0]['publicKey'],signing_key_ref=ref('issuer'),
            service_identity_ref=ref('service'),service_instance_id='ingress-one',now=NOW)
        args.update(changes)
        return verify_capability_response(response,request or self.signed(),**args)

    async def test_signed_reply_binds_complete_request_and_data(self):
        raw=self.signed(); response=await self.call(raw)
        value=strict_loads(self.verify(response,raw))
        self.assertEqual(strict_loads(base64.b64decode(value['data'])),self.original)
        signed=strict_loads(response)['claims']
        self.assertEqual(signed['requestDigest'],_digest(raw))
        self.assertEqual(signed['envelopeDigest'],_digest(self.inner))
        self.assertLessEqual(len(response),65536)
        self.assertNotIn('hub-one',repr(self.reply_service))

    async def test_reply_expires_with_signing_issuer(self):
        expiry=NOW+timedelta(seconds=1)
        latest=self.js.messages[-1]
        current=strict_loads(latest.data)
        current['state']['issuers'][0]['expiresAt']=expiry.isoformat().replace('+00:00','Z')
        latest.data=canonical_bytes(current)
        response=await self.call()
        self.assertEqual(strict_loads(response)['claims']['validUntil'],
                         expiry.isoformat(timespec='microseconds').replace('+00:00','Z'))
        with self.assertRaises(ContractError):self.verify(response,now=expiry)

    async def test_reply_redirect_refused_before_receiver(self):
        with patch.object(self.reply_service._receiver,'handle',side_effect=AssertionError('must not dispatch')):
            with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call(reply='_INBOX.otherrecipient1234')

    async def test_outer_and_inner_bindings_and_closed_schema(self):
        original=copy.deepcopy(self.wrapper)
        for field,value in [('profileId','other'),('operationId','other'),('requestId','other'),('serviceId','artifact-owner'),
                            ('nativeFactsDigest','sha256:'+'0'*64),('hostTransportRef',ref('transport')),
                            ('extra','private'),('scope',{'organizationId':'org-one','projectId':'other','workspaceId':None})]:
            self.wrapper=copy.deepcopy(original);self.wrapper[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()
        self.wrapper=original
        with self.assertRaises(ContractError):await self.call(self.signed()+b' ')
        with self.assertRaises(ContractError):await self.call(b'x'*(REQUEST_LIMIT+1))

    async def test_current_host_transport_revocation_refuses(self):
        self.claims.update(operationId='revoke-host',contractId='identity-revoke',grantRef=ref('grant'),
            expectedVersion=2,payload={'authorityId':'authority-one','targetRef':ref('host-transport')})
        result=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):await self.call()

    async def test_current_revocation_after_read_withholds_signature(self):
        original=self.data_js.stream_info
        revoked=False
        async def revoke(*args,**kwargs):
            nonlocal revoked
            if not revoked:
                revoked=True
                self.claims.update(operationId='revoke-after-read',contractId='identity-revoke',grantRef=ref('grant'),
                    expectedVersion=2,payload={'authorityId':'authority-one','targetRef':ref('host-transport')})
                await self.service.handle(self.request())
            return await original(*args,**kwargs)
        self.data_js.stream_info=revoke
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):await self.call()
        self.assertTrue(revoked)

    async def test_reply_replay_tampering_and_wrong_enrolled_signer_refuse(self):
        raw=self.signed();response=await self.call(raw)
        for key,value in [('replySubject','_INBOX.otherrecipient1234'),('requestId','other')]:
            changed=copy.deepcopy(self.wrapper);changed[key]=value
            other=canonical_bytes({'schemaVersion':'1.0.0','algorithm':'Ed25519','canonicalization':'RFC8785-JCS-UTF8',
                'claims':changed,'signature':sign_claims(changed,SEED)})
            with self.assertRaisesRegex(ContractError,'^capability_reply_unconfirmed$'):self.verify(response,other)
        for values in ({'now':NOW+timedelta(seconds=4)},{'signing_key_ref':ref('other')},
                       {'service_instance_id':'other'},{'service_identity_ref':ref('host')}):
            with self.assertRaises(ContractError):self.verify(response,raw,**values)
        altered=strict_loads(response);altered['claims']['payload']['data']='cHJpdmF0ZQ=='
        with self.assertRaises(ContractError):self.verify(canonical_bytes(altered),raw)

    async def test_inner_numeric_tokens_remain_exact_bytes(self):
        changed=self.inner.replace(b'"revision":1',b'"revision":1.000')
        self.assertNotEqual(changed,self.inner)
        self.wrapper['envelopeBytes']=base64.b64encode(changed).decode()
        response=await self.call()
        self.assertEqual(strict_loads(response)['claims']['envelopeDigest'],_digest(changed))
        self.verify(response)

    async def test_transport_size_and_bound_reply_subject(self):
        self.connection.max_payload=65536
        with self.assertRaisesRegex(ContractError,'^capability_service_frame_limit$'):
            await self.reply_service.start()
        self.connection.max_payload=1048576
        await self.reply_service.start()
        self.assertEqual(self.connection.options['pending_bytes_limit'],32*REQUEST_LIMIT)
        await self.reply_service._receive(SimpleNamespace(reply='_INBOX.otherrecipient1234',data=self.signed()))
        self.assertEqual(self.connection.sent,[])
        await self.reply_service._receive(SimpleNamespace(reply=self.wrapper['replySubject'],data=self.signed()))
        self.assertEqual(len(self.connection.sent),1)
        self.verify(self.connection.sent[0][1])
        await self.reply_service.close()
        self.assertEqual(self.connection.subscription.drains,1)

    async def test_close_drains_queued_messages_with_real_nats_delivery_worker(self):
        from nats.aio.subscription import Subscription as NatsSubscription
        entered=asyncio.Event()
        pending=asyncio.Event()
        errors=[]
        removed=[]
        async def unsubscribe(sid):
            pass
        async def on_error(error):
            errors.append(error)
        self.connection.is_closed=False
        self.connection.is_draining=False
        self.connection._send_unsubscribe=unsubscribe
        self.connection._remove_sub=removed.append
        async def subscribe(subject, **options):
            subscription=NatsSubscription(self.connection,id=7,subject=subject,**options)
            subscription._start(on_error)
            self.connection.subscription=subscription
            return subscription
        self.connection.subscribe=subscribe
        await self.reply_service.start()
        subscription=self.connection.subscription
        worker=subscription._wait_for_msgs_task
        async def blocked_read(raw, **kwargs):
            self.assertIsNot(asyncio.current_task(),worker)
            entered.set()
            await pending.wait()
        with patch.object(self.reply_service._receiver,'handle',side_effect=blocked_read) as read:
            for _ in range(3):
                message=SimpleNamespace(data=self.signed(),reply=self.wrapper['replySubject'])
                subscription._pending_size+=len(message.data)
                subscription._pending_queue.put_nowait(message)
            await asyncio.wait_for(entered.wait(),2)
            await self.reply_service.close(timeout=1)
            await asyncio.wait_for(subscription._pending_queue.join(),1)
            await asyncio.wait_for(worker,1)
            self.assertEqual(read.call_count,1)
        self.assertEqual(removed,[7])
        self.assertEqual(errors,[])
        self.assertEqual(self.connection.sent,[])
        self.assertEqual(subscription._pending_queue.qsize(),0)
        self.assertFalse(self.reply_service._active)
        self.assertFalse(self.reply_service._callbacks)

    async def test_close_retries_failed_drain_on_original_subscription(self):
        await self.reply_service.start()
        original=self.connection.subscription
        drain=original.drain
        attempts=0
        async def transient():
            nonlocal attempts
            attempts+=1
            if attempts==1:
                raise RuntimeError('private broker diagnostic')
            await drain()
        original.drain=transient
        with self.assertRaisesRegex(ContractError,'^capability_cleanup_incomplete$'):
            await self.reply_service.close()
        failed=self.reply_service._cleanup_task
        self.assertTrue(failed.done())
        await self.reply_service.close()
        self.assertIs(self.reply_service._subscription,original)
        self.assertIsNot(self.reply_service._cleanup_task,failed)
        self.assertEqual(attempts,2)
        self.assertEqual(original.drains,1)

    async def test_terminal_subscribe_failure_joins_original_allocated_subscription(self):
        from unittest.mock import AsyncMock
        original = self.connection.subscription
        original.unsubscribe = AsyncMock()
        async def failed(owner, subject, **options):
            owner.own_subscription(original)
            raise OSError('private SUB send fault')
        self.connection.subscribe_owned = failed
        with self.assertRaisesRegex(ContractError, '^capability_service_unavailable$'):
            await self.reply_service.start()
        allocation = self.reply_service._subscribe_task
        await self.reply_service.close()
        self.assertIs(self.reply_service._subscribe_task, allocation)
        self.assertIsInstance(allocation.exception(), OSError)
        original.unsubscribe.assert_awaited_once()
        self.assertTrue(self.reply_service._subscriptions.close_task.done())
        self.assertFalse(self.reply_service._receiver._workers)

    async def test_close_joins_original_stalled_subscription(self):
        self.connection.release.clear()
        start=asyncio.create_task(self.reply_service.start())
        await self.connection.subscribed.wait()
        try:
            with self.assertRaisesRegex(ContractError,'^capability_cleanup_incomplete$'):
                await self.reply_service.close(timeout=0.01)
            original=self.reply_service._cleanup_task
            self.assertFalse(original.done())
        finally:
            self.connection.release.set()
            with self.assertRaises(ContractError):await start
            await self.reply_service.close(timeout=2)
        self.assertIs(self.reply_service._cleanup_task,original)
        self.assertEqual(self.connection.subscription.drains,1)
