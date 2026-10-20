"""Private-child reads through real retained enrollment and receiving gates.

Only broker I/O is controlled offline. The shared identity lineage validator and
actual provider/receiver run here; Go separately owns package/lifetime intersection.
"""
import base64
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import NOW, ref
from identity import test_native_bridge as native_tests
from identity.native_bridge import verify_response
from . import test_reply_service as reply_tests


class PrivateReadTests(unittest.IsolatedAsyncioTestCase):
    request=native_tests.NativeBridgeTests.request
    bridge_request=native_tests.NativeBridgeTests.bridge_request
    signed=reply_tests.ReplyServiceTests.signed
    call=reply_tests.ReplyServiceTests.call
    verify=reply_tests.ReplyServiceTests.verify

    def setUp(self):
        reply_tests.ReplyServiceTests.setUp(self)
        self.parent=copy.deepcopy(self.row)
        self.parent.update(ref=ref('native-parent'),identityRef=ref('parent-plugin'))
        self.parent['owner'].update(instanceId='parent-one',epoch='c'*64)
        self.parent['facts']['grant'].update(grantId='parent-grant',subjectInstanceId='parent-one')
        self.parent['facts']['policy']['subjectInstanceId']='parent-one'
        self.row.update(relationship='private',parentOwner=copy.deepcopy(self.parent['owner']))
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['grant']['parentGrantRef']=ref('parent-grant')
        self.row['facts']['parentAccess']=[{'action':'read','resourceClass':'storage','resourceId':'task-one'}]
        state=self.record['state']
        state['identities'].append({'ref':ref('parent-plugin'),'status':'active','kind':'plugin',
                                   'principalId':'parent-one','externalIdentity':None})
        for method in ('bind-instance','admit-operation','recheck','prepare-domain-call'):
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref('parent-host-'+method),callerRef=ref('host'),actorRef=ref('host'),
                contractId='native-authority-'+method,resourceId='parent-one')
            state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)

    async def enroll(self):
        for index,row in enumerate((self.parent,self.row)):
            self.claims.update(operationId='enroll-'+row['owner']['instanceId'],expectedVersion=1+index,
                contractId='identity-native-instance-set',grantRef=ref('native-admin'),
                payload={'authorityId':'authority-one','record':row,'previousRef':None})
            response=strict_loads(await self.service.handle(self.request()))
            self.assertEqual(response['claims']['receipt']['decision'],'allowed')

    async def asyncSetUp(self):
        await reply_tests.ReplyServiceTests.asyncSetUp(self)

    def retained_change(self,change):
        latest=self.js.messages[-1]
        current=strict_loads(latest.data)
        change(current['state'])
        latest.data=canonical_bytes(current)

    async def prepare_private(self):
        admitted_request=self.bridge_request('admit-operation',{
            'envelopeBytes':base64.b64encode(self.inner).decode(),
            'audience':{'hubId':'hub-one','serviceId':'storage-owner'}})
        def verified(raw,request):
            return verify_response(raw,request,public_key=self.record['state']['issuers'][0]['publicKey'],
                                   signing_key_ref=ref('issuer'),now=NOW)['result']
        admitted=verified(await self.service.native.handle(admitted_request),admitted_request)
        prepare=self.bridge_request('prepare-domain-call',{
            'operation':admitted['operation'],'operationAuthorityRef':admitted['authorityRef'],
            'bindingId':'storage-read','contractId':'capability-storage-read',
            'serviceRequestId':'request_'+'e'*64,'serviceReplySubject':self.wrapper['replySubject'],
            'payload':{'resourceRef':ref('task-one'),'input':{}},
            'originalEnvelopeBytes':base64.b64encode(self.inner).decode()})
        result=verified(await self.service.native.handle(prepare),prepare)
        raw=base64.b64decode(result['serviceRequestBytes'])
        self.wrapper=strict_loads(raw)['claims']
        self.inner=base64.b64decode(self.wrapper['envelopeBytes'])
        return raw

    async def test_private_child_prepared_by_actual_provider_reads_original_record(self):
        raw=await self.prepare_private()
        response=await self.call(raw)
        payload=strict_loads(self.verify(response,raw))
        self.assertEqual(strict_loads(base64.b64decode(payload['data'])),self.original)

    async def test_parent_owner_and_current_grant_substitutions_refuse_before_read(self):
        original=self.js.messages[-1].data
        def child(state):return state['nativeInstances'][1]
        changes={
            'parent-generation':lambda s:child(s)['parentOwner'].update(generation=2),
            'parent-epoch':lambda s:child(s)['parentOwner'].update(epoch='f'*64),
            'parent-pin':lambda s:child(s)['parentOwner']['pin'].update(packageChecksum='sha256:'+'f'*64),
            'grant-revision':lambda s:s['nativeInstances'][0]['facts']['grant'].update(revision=2),
            'parent-row-revoked':lambda s:s['nativeInstances'][0].update(status='revoked'),
            'missing-parent':lambda s:s['nativeInstances'].pop(0)}
        for name,change in changes.items():
            self.js.messages[-1].data=original
            self.retained_change(change)
            with self.subTest(binding=name),patch.object(self.reply_service._receiver,'handle') as read:
                with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                    await self.call()
                read.assert_not_called()
        self.js.messages[-1].data=original

    async def test_child_scope_action_resource_and_lifetime_widening_refuse(self):
        original=self.js.messages[-1].data
        def grant(state):return state['nativeInstances'][1]['facts']['grant']
        changes={
            'action':lambda s:grant(s)['actions'].append('write'),
            'resource':lambda s:grant(s)['resourceIds'].append('task-other'),
            'scope':lambda s:grant(s)['scope'].update(projectId='other-project'),
            'lifetime':lambda s:grant(s).update(expiresAt='2026-10-09T12:11:00Z')}
        for name,change in changes.items():
            self.js.messages[-1].data=original
            self.retained_change(change)
            current=strict_loads(self.js.messages[-1].data)['state']['nativeInstances'][1]
            self.wrapper['nativeFactsDigest']=payload_digest(current['facts'])
            with self.subTest(widening=name),self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()
        self.js.messages[-1].data=original

    async def test_parent_tuple_denial_and_unresolved_approval_refuse(self):
        original=self.js.messages[-1].data
        for outcome in ('deny','approval_required'):
            self.js.messages[-1].data=original
            self.retained_change(lambda s:s['nativeInstances'][0]['facts']['policy']['decisions'].append({
                'access':{'action':'read','resourceClass':'storage','resourceId':'task-one'},'outcome':outcome}))
            with self.subTest(outcome=outcome),self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
                await self.call()
        self.js.messages[-1].data=original

    async def test_private_reply_is_bounded_by_parent_policy_expiry(self):
        expiry=(NOW+timedelta(seconds=1)).isoformat().replace('+00:00','Z')
        self.retained_change(lambda s:s['nativeInstances'][0]['facts']['policy'].update(expiresAt=expiry))
        raw=await self.prepare_private()
        response=await self.call(raw)
        self.assertEqual(strict_loads(response)['claims']['validUntil'],
                         (NOW+timedelta(seconds=1)).isoformat(timespec='microseconds').replace('+00:00','Z'))

    async def test_parent_revocation_during_read_withholds_signed_reply(self):
        raw=await self.prepare_private()
        original=self.data_js.stream_info
        revoked=False
        async def revoke(*args,**kwargs):
            nonlocal revoked
            if not revoked:
                revoked=True
                self.claims.update(operationId='revoke-parent',expectedVersion=3,
                    contractId='identity-revoke',grantRef=ref('grant'),
                    payload={'authorityId':'authority-one','targetRef':ref('parent-plugin')})
                response=strict_loads(await self.service.handle(self.request()))
                self.assertEqual(response['claims']['receipt']['decision'],'allowed')
            return await original(*args,**kwargs)
        self.data_js.stream_info=revoke
        with self.assertRaisesRegex(ContractError,'^capability_service_unavailable$'):
            await self.call(raw)
        self.assertTrue(revoked)
