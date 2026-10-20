"""Control authentication preserves original allocation cleanup after revocation."""
import copy
from datetime import timedelta
import unittest
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.test_authority import ref, NOW
from identity.test_native_bridge import HOST_SEED
from identity import test_native_subscriptions as support
from identity.configuration_subscription_control import evaluate_control


class SubscriptionControlTests(unittest.IsolatedAsyncioTestCase):
    setUp=support.NativeSubscriptionTests.setUp
    enroll=support.NativeSubscriptionTests.enroll
    request=support.NativeSubscriptionTests.request
    bridge_request=support.NativeSubscriptionTests.bridge_request
    operation_envelope=support.NativeSubscriptionTests.operation_envelope
    prepare=support.NativeSubscriptionTests.prepare

    async def opening(self):
        import base64
        await self.prepare()
        envelope=strict_loads(base64.b64decode(self.inp['subscriptionEnvelopeBytes']))
        self.claims_control={'purpose':'agentmux-configuration-subscription-control-v1','action':'open',
            'requestId':'request_'+'a'*64,'openRequestId':'request_'+'a'*64,'leaseId':None,
            'owner':copy.deepcopy(self.row['owner']),'operationId':envelope['operation']['operationId'],
            'approvedEnvelopeDigest':payload_digest(envelope),'filterDigest':envelope['payload']['filterDigest'],
            'cursor':envelope['payload']['cursor'],'signingKeyRef':ref('host-transport'),
            'issuedAt':NOW.isoformat().replace('+00:00','Z'),
            'expiresAt':(NOW+timedelta(seconds=4)).isoformat().replace('+00:00','Z'),
            'subscriptionEnvelopeBytes':self.inp['subscriptionEnvelopeBytes'],
            'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
            'replySubject':'_INBOX.abcdefghijklmnop.'+'a'*64}
        self.snapshot=await self.service.reader.current()
        self.opened=self.check()
        return self.opened

    def encoded(self,seed=HOST_SEED):
        return canonical_bytes({'schemaVersion':'1.0.0','algorithm':'Ed25519','canonicalization':'RFC8785-JCS-UTF8',
            'claims':self.claims_control,'signature':sign_claims(self.claims_control,seed)})

    def check(self,**kwargs):
        return evaluate_control(self.snapshot,self.encoded(),now=NOW,
            reply_subject=self.claims_control['replySubject'],**kwargs)

    def control(self,action):
        self.claims_control.pop('subscriptionEnvelopeBytes',None)
        self.claims_control.update(action=action,requestId='request_'+'b'*64,leaseId='lease-one')

    async def test_open_and_next_need_current_original_subscription_authority(self):
        opened=await self.opening()
        self.assertTrue(opened.can_read)
        self.control('next')
        admitted=self.check(allocation=opened.allocation,expected_cursor=self.claims_control['cursor'],expected_lease_id='lease-one')
        self.assertTrue(admitted.can_read)
        latest=strict_loads(self.js.messages[-1].data)
        next(g for g in latest['state']['grants'] if g['ref']==ref('subscriber'))['decision']='denied'
        self.js.messages[-1].data=canonical_bytes(latest);self.snapshot=await self.service.reader.current()
        with self.assertRaisesRegex(ContractError,'subscription_control_not_authorized'):
            self.check(allocation=opened.allocation,expected_cursor=self.claims_control['cursor'],expected_lease_id='lease-one')

    async def test_lost_open_close_is_cleanup_only_after_expiry_without_snapshot(self):
        opened=await self.opening();self.control('close');self.claims_control['leaseId']=None
        later=NOW+timedelta(seconds=20)
        self.claims_control.update(issuedAt=later.isoformat().replace('+00:00','Z'),
            expiresAt=(later+timedelta(seconds=4)).isoformat().replace('+00:00','Z'))
        admitted=evaluate_control(None,self.encoded(),now=later,
            reply_subject=self.claims_control['replySubject'],allocation=opened.allocation)
        self.assertFalse(admitted.can_read)
        self.assertEqual(admitted.action,'close')
        self.assertIs(admitted.allocation,opened.allocation)
        with self.assertRaisesRegex(ContractError,'subscription_control_allocation_required'):
            evaluate_control(None,self.encoded(),now=later,reply_subject=self.claims_control['replySubject'])

    async def test_next_refuses_revoked_host_even_when_close_can_join(self):
        opened=await self.opening();self.control('next')
        latest=strict_loads(self.js.messages[-1].data)
        next(t for t in latest['state']['transports'] if t['ref']==ref('host-transport'))['status']='revoked'
        self.js.messages[-1].data=canonical_bytes(latest);self.snapshot=await self.service.reader.current()
        with self.assertRaisesRegex(ContractError,'subscription_control_transport_unavailable'):
            self.check(allocation=opened.allocation,expected_cursor=self.claims_control['cursor'],expected_lease_id='lease-one')
        self.control('close')
        self.assertFalse(self.check(allocation=opened.allocation,expected_lease_id='lease-one').can_read)

    async def test_wrong_owner_open_id_digest_source_lease_or_signature_cannot_close(self):
        opened=await self.opening();self.control('close');original=copy.deepcopy(self.claims_control)
        for mutate in (lambda c:c['owner'].update(generation=2),
                       lambda c:c.update(openRequestId='request_'+'c'*64),
                       lambda c:c.update(approvedEnvelopeDigest='sha256:'+'d'*64),
                       lambda c:c['cursor'].update(sourceDigest='sha256:'+'e'*64),
                       lambda c:c.update(leaseId='other-lease')):
            self.claims_control=copy.deepcopy(original);mutate(self.claims_control)
            with self.assertRaises(ContractError):self.check(allocation=opened.allocation,expected_lease_id='lease-one')
        self.claims_control=original
        with self.assertRaises(ContractError):
            evaluate_control(None,self.encoded(bytes([22])*32),now=NOW,
                reply_subject=self.claims_control['replySubject'],allocation=opened.allocation,expected_lease_id='lease-one')

    async def test_next_requires_service_cursor_and_reply_subject_is_signed(self):
        opened=await self.opening();self.control('next')
        with self.assertRaisesRegex(ContractError,'subscription_control_cursor_binding'):
            self.check(allocation=opened.allocation,expected_cursor=dict(self.claims_control['cursor'],sequence=2),
                expected_lease_id='lease-one')
        with self.assertRaisesRegex(ContractError,'subscription_control_reply_binding'):
            evaluate_control(self.snapshot,self.encoded(),now=NOW,reply_subject='_INBOX.other.'+'a'*64,
                allocation=opened.allocation,expected_cursor=self.claims_control['cursor'],expected_lease_id='lease-one')
