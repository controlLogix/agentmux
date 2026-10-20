"""Actual native enrollment and parent checks at board journal admission."""
import base64
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.fed.board_services import _BoardOperations
from identity import test_native_bridge as native_support
from identity import test_service as service_tests
from identity.test_authority import ref, NOW, SEED
from . import test_board_journal as journal_tests
from .board_journal import claim_marker


class NativeBoardJournalTests(unittest.IsolatedAsyncioTestCase):
    open=journal_tests.BoardJournalTests.open
    admit=journal_tests.BoardJournalTests.admit

    def setUp(self):
        journal_tests.BoardJournalTests.setUp(self)
        self.row=native_support.native_row()
        self.row['facts']['grant'].update(scope=copy.deepcopy(self.scope),actions=['write'])
        self.row['facts']['policy'].update(scope=copy.deepcopy(self.scope),decisions=[{
            'access':{'action':'write','resourceClass':'storage','resourceId':'task-one'},'outcome':'allow'}])
        self.row['facts']['domainBindings']=[{'id':'board-write','contractId':'capability-storage-write',
            'action':'write','resourceClass':'storage','resourceIds':['task-one']}]
        self.parent=copy.deepcopy(self.row)
        self.parent.update(ref=ref('parent-row'),identityRef=ref('parent-plugin'))
        self.parent['owner'].update(instanceId='parent-one',epoch='c'*64)
        self.parent['facts']['grant'].update(grantId='parent-grant',subjectInstanceId='parent-one',
                                           policyRef=ref('parent-policy'))
        self.parent['facts']['policy'].update(reference=ref('parent-policy'),subjectInstanceId='parent-one')
        self.row.update(relationship='private',parentOwner=copy.deepcopy(self.parent['owner']))
        self.row['facts']['parentGrant']=copy.deepcopy(self.parent['facts']['grant'])
        self.row['facts']['grant']['parentGrantRef']=ref('parent-grant')
        self.row['facts']['parentAccess']=[copy.deepcopy(self.parent['facts']['policy']['decisions'][0]['access'])]
        state=self.record['state']
        for name,kind in (('host','service'),('plugin','plugin'),('parent-plugin','plugin')):
            state['identities'].append({'ref':ref(name),'kind':kind,'principalId':name+'-one',
                                       'status':'active','externalIdentity':None})
        transport=copy.deepcopy(state['transports'][0]);transport.update(ref=ref('host-transport'),
            identityRef=ref('host'),publicKey=base64.urlsafe_b64encode(
                bytes(SigningKey(native_support.HOST_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        member=copy.deepcopy(state['memberships'][0]);member.update(ref=ref('host-member'),
            identityRef=ref('host'),scope=copy.deepcopy(self.scope))
        state['memberships'].append(member)
        admin=copy.deepcopy(state['grants'][0]);admin.update(ref=ref('native-admin'),
            contractId='identity-native-instance-set',resourceId='authority-one')
        state['grants'].append(admin)
        grant=copy.deepcopy(admin);grant.update(ref=ref('host-prepare'),callerRef=ref('host'),actorRef=ref('host'),
            scope=copy.deepcopy(self.scope),contractId='native-authority-prepare-domain-call',resourceId='plugin-one')
        state['grants'].append(grant)
        grant=copy.deepcopy(grant);grant.update(ref=ref('host-parent-recheck'),
            contractId='native-authority-recheck',resourceId='parent-one')
        state['grants'].append(grant)
        self.js.messages[0].data=canonical_bytes(self.record)

    async def set_row(self, row, previous=None):
        self.claims.update(operationId='set-'+row['ref']['id']+'-'+str(row['ref']['revision']),
            contractId='identity-native-instance-set',grantRef=ref('native-admin'),
            expectedVersion=len(self.js.messages),payload={
                'authorityId':'authority-one','record':row,'previousRef':previous})
        result=strict_loads(await self.service.handle(service_tests.ServiceTests.request(self)))
        self.assertEqual(result['claims']['receipt']['decision'],'allowed')

    async def asyncSetUp(self):
        await self.set_row(self.parent)
        await self.set_row(self.row)

    def wrapper(self, raw):
        envelope=strict_loads(raw)
        claims={'purpose':'agentmux-capability-service-request-v1','requestId':envelope['correlationId'],
            'profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one','owner':self.row['owner'],
            'serviceId':'storage-owner','requestContractId':'capability-storage-write',
            'replyContractId':'capability-storage-write-reply','operationId':envelope['operation']['operationId'],
            'resourceRef':self.target,'scope':copy.deepcopy(self.scope),'replySubject':'_INBOX.abcdefghijklmnop',
            'issuedAt':NOW.isoformat().replace('+00:00','Z'),
            'validUntil':(NOW+timedelta(seconds=4)).isoformat().replace('+00:00','Z'),
            'signingKeyRef':ref('issuer'),'hostTransportRef':ref('host-transport'),
            'nativeFactsDigest':payload_digest(self.row['facts']),'envelopeBytes':base64.b64encode(raw).decode()}
        return canonical_bytes({'schemaVersion':'1.0.0','algorithm':'Ed25519',
            'canonicalization':'RFC8785-JCS-UTF8','claims':claims,'signature':sign_claims(claims,SEED)})

    async def candidate(self):
        raw=await self.admit('capability-storage-write','native-board-write',7,
            {'resourceRef':self.target,'input':{'value':{'command':'comment','text':'one'}}})
        card={'key':'SH-1','rid':'r0123456789ab','status':'todo',
              '_agentmuxOperation':claim_marker(strict_loads(raw))}
        candidate=_BoardOperations().prepare_change(None,card['rid'],card,{'command':'comment','text':'one'},
            by='peer:nick',at='2026-10-09T12:00:01Z')
        return raw,candidate

    async def test_actual_private_child_wrapper_preserves_original_caller_operation(self):
        raw,candidate=await self.candidate()
        stored=await self.journal.prepare(raw,expected_sequence=0,candidate=candidate,
            target_ref=self.target,observed_sequence=7,service_request_bytes=self.wrapper(raw))
        state=strict_loads(stored.record)
        self.assertEqual(state['operation'],strict_loads(raw)['operation'])
        self.assertEqual(state['state']['original'],strict_loads(raw))
        self.assertEqual(state['operation']['caller']['authenticatedIdentityRef'],ref('human'))

    async def test_missing_or_detached_native_wrapper_cannot_append(self):
        raw,candidate=await self.candidate()
        with self.assertRaisesRegex(ContractError,'board_journal_native_required'):
            await self.journal.prepare(raw,expected_sequence=0,candidate=candidate,
                target_ref=self.target,observed_sequence=7)
        other=strict_loads(raw);other['correlationId']='different'
        with self.assertRaisesRegex(ContractError,'board_journal_access_refused'):
            await self.journal.prepare(raw,expected_sequence=0,candidate=candidate,
                target_ref=self.target,observed_sequence=7,service_request_bytes=self.wrapper(canonical_bytes(other)))
        self.assertEqual(self.journal_js.messages,[])

    async def test_parent_withdrawal_during_final_authority_recheck_prevents_append(self):
        raw,candidate=await self.candidate()
        wrapper=self.wrapper(raw)
        current=self.service.reader.current
        calls=0
        async def changed():
            nonlocal calls
            calls+=1
            if calls==2:
                parent=copy.deepcopy(self.parent);previous=copy.deepcopy(parent['ref'])
                parent['ref']['revision']+=1;parent['status']='revoked'
                await self.set_row(parent,previous)
            return await current()
        with patch.object(self.service.reader,'current',side_effect=changed):
            with self.assertRaises(ContractError):
                await self.journal.prepare(raw,expected_sequence=0,candidate=candidate,
                    target_ref=self.target,observed_sequence=7,service_request_bytes=wrapper)
        self.assertGreaterEqual(calls,2)
        self.assertEqual(self.journal_js.messages,[])

    async def test_oversized_frames_refuse_before_parse_or_wrapper_decode(self):
        from .board_journal import ORIGINAL_CONTRACTS
        with patch('capability_owner.board_journal.strict_loads') as parse:
            with self.assertRaisesRegex(ContractError,'board_journal_invalid'):
                await self.journal._authorize(b' '*65537,ORIGINAL_CONTRACTS)
            parse.assert_not_called()
        raw,_=await self.candidate()
        with patch('capability_owner.board_journal.base64.b64decode') as decode:
            with self.assertRaisesRegex(ContractError,'board_journal_invalid'):
                await self.journal._authorize(raw,ORIGINAL_CONTRACTS,b' '*98305)
            decode.assert_not_called()
        self.assertEqual(self.journal_js.messages,[])
