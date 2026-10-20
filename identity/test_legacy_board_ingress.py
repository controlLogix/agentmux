"""Real Hub proofs and enrolled ingress keep legacy attribution separate."""
import copy
import hashlib
import json
import os
import weakref
from contextvars import ContextVar
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.server import Hub
from hub.store import HubError
from identity import test_service as support
from identity.test_authority import ref, SEED
from identity.legacy_board_ingress import LegacyBoardIngress, LegacyBoardCallerEnrollment, LegacyBoardRoute


class LegacyBoardIngressTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.ServiceTests.setUp(self)
        patch('identity.legacy_board_ingress.datetime',support._Clock).start()
        self.hub=object.__new__(Hub)
        self.hub._authenticated_callers=weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context=ContextVar('board_caller',default=None)
        self.hub.operator_sha=hashlib.sha256(b'operator-secret').hexdigest()
        self.hub.peer=Mock(return_value=(1,os.getuid()))
        self.hub.db=AsyncMock(return_value=(None,False))
        self.writer=SimpleNamespace(get_extra_info=lambda key:object())
        grant=copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('board-grant'),contractId='federation-board-command',resourceId='board-one')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        self.enrollment=LegacyBoardCallerEnrollment('operator','profile-one','hub-one','authority-one',
            grant['callerRef'],ref('transport'),bytes(reversed(SEED)),tuple(
                LegacyBoardRoute('falcon',key,ref('board-one'),ref('board-grant'),grant['scope'])
                for key in ('SH-1',None)))
        self.adapter=LegacyBoardIngress(self.hub,self.service.ingress,self.enrollment)

    async def proof(self,verb='fed_board_comment',args=None,attribution='worker'):
        return await self.hub.authenticate_caller({'verb':verb,'args':args or {'repo':'falcon','key':'SH-1','text':'hello'},
            'as':attribution},self.writer,False)

    async def admit(self,proof):
        return await self.adapter.admit_local(proof,operation_id='board-operation',expected_version=3,
            cancellation_ref=ref('board-cancel'))

    async def test_actual_connection_preserves_authenticated_operator_and_attributed_worker(self):
        request={'verb':'fed_board_comment','args':{'repo':'falcon','key':'SH-1','text':'hello'},'as':'worker'}
        reader=SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
        writer=SimpleNamespace(get_extra_info=lambda key:object(),write=Mock(),drain=AsyncMock(),close=Mock())
        received=[]
        async def dispatch(verb,args,caller):
            self.assertEqual(caller,'worker')
            admitted=await self.admit(self.hub.current_authenticated_caller())
            received.append(strict_loads(admitted.envelope))
            return {'admitted':True}
        self.hub.dispatch=dispatch
        await self.hub.handle_conn(reader,writer)
        self.assertTrue(json.loads(writer.write.call_args.args[0])['ok'])
        event=received[0]
        self.assertEqual(event['payload'],{'resourceRef':dict(ref('board-one'),revision=3),
            'attribution':'worker','input':{'command':'comment','key':'SH-1','text':'hello'}})
        self.assertEqual(event['operation']['caller']['authenticatedIdentityRef'],strict_loads(self.enrollment.identity_ref))
        self.assertNotEqual(event['operation']['caller']['principalId'],'worker')
        self.assertEqual(event['destinationServiceId'],'storage-owner')
        self.assertEqual(event['operation']['effectiveActorRef'],strict_loads(self.enrollment.identity_ref))

    async def test_recognized_commands_are_derived_and_owner_phases_refuse(self):
        for command,args in [('add',{'title':'new','body':'body','labels':['one'],'from':'TM-1'}),
                             ('move',{'key':'SH-1','status':'review'}),('assign',{'key':'SH-1','to':'peer:one'}),
                             ('claim',{'key':'SH-1'})]:
            admitted=await self.admit(await self.proof('fed_board_'+command,args))
            self.assertEqual(strict_loads(admitted.envelope)['payload']['input'],{'command':command,**args})
        for verb in ('fed_board_dispatch','fed_board_complete','fed_board_list'):
            with self.assertRaisesRegex(ContractError,'legacy_board_command_unavailable'):
                await self.admit(await self.proof(verb))

    async def test_wrong_route_actor_or_replaced_command_fields_refuse(self):
        for args in ({'repo':'other','key':'SH-1','text':'hello'}, {'key':'OTHER','text':'hello'},
                     {'key':'SH-1','text':'hello','resourceRef':ref('other')},
                     {'key':'SH-1','text':'hello','attribution':'operator'}):
            with self.assertRaises(ContractError):await self.admit(await self.proof(args=args))
        self.hub.db.return_value=('agent',True)
        with self.assertRaisesRegex(ContractError,'legacy_board_caller_binding'):
            await self.admit(await self.proof(attribution=None))

    async def test_proof_replay_current_grant_denial_and_transport_rebinding_refuse(self):
        proof=await self.proof();self.assertIsNotNone((await self.admit(proof)).envelope)
        with self.assertRaises(HubError):await self.admit(proof)
        grant=next(g for g in self.record['state']['grants'] if g['ref']==ref('board-grant'))
        grant['decision']='denied';self.js.messages[0].data=canonical_bytes(self.record)
        denied=await self.admit(await self.proof());self.assertIsNone(denied.envelope)
        grant['decision']='allowed'
        self.record['state']['transports'][0]['identityRef']=ref('service')
        self.js.messages[0].data=canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError,'legacy_board_enrollment_binding'):
            await self.admit(await self.proof())

    async def test_owner_phases_use_separate_service_grants_and_journal_revision(self):
        import base64
        from nacl.signing import SigningKey
        from agentmux_contracts import sign_claims
        from identity.test_authority import NOW
        from datetime import timedelta
        state=self.record['state'];seed=bytes([7])*32
        transport=copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('owner-transport'),identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        member=copy.deepcopy(state['memberships'][0]);member.update(ref=ref('owner-member'),identityRef=ref('service'))
        state['memberships'].append(member)
        for contract in ('federation-board-dispatch','federation-board-complete'):
            grant=copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(contract),callerRef=ref('service'),actorRef=ref('service'),
                contractId=contract,resourceId='board-one')
            state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)
        for contract in ('federation-board-dispatch','federation-board-complete'):
            payload={'resourceRef':dict(ref('board-one'),revision=8),'journalRef':dict(ref('journal'),revision=2),
                'claimRef':ref('claim'),'originalOperationId':'board-operation',
                'originalPayloadDigest':'sha256:'+'a'*64,'candidateDigest':'sha256:'+'b'*64}
            if contract.endswith('complete'):payload['observationId']='observation-one'
            claims={'purpose':'agentmux-client-possession-v1','profileId':'profile-one','hubId':'hub-one',
                'authorityId':'authority-one','transportRef':ref('owner-transport'),'grantRef':ref(contract),
                'operationId':'phase-operation','expectedVersion':2,'contractId':contract,'payload':payload,
                'approvalRefs':[],'issuedAt':NOW.isoformat().replace('+00:00','Z'),
                'expiresAt':(NOW+timedelta(seconds=4)).isoformat().replace('+00:00','Z')}
            async def admit():
                raw=canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,seed)})
                return await self.service.ingress.admit(raw,cancellation_ref=ref('phase-cancel'))
            self.assertIsNotNone((await admit()).envelope)
            claims['expectedVersion']=8
            self.assertIsNone((await admit()).envelope)
            claims['expectedVersion']=2;claims['payload']['resourceRef']['id']='other-board'
            self.assertIsNone((await admit()).envelope)
