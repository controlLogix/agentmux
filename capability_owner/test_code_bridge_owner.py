"""Signed code commands reach the original owner through controlled transport."""
import asyncio
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.fed import guard, ledger
from hub.fed.plugins.code import Code
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .code import CodeStorageResource
from .code_legacy import LegacyCodeActor
from .code_bridge_service import CodeBridgeService, verify_code_bridge_reply
from . import test_message_bridge_owner as message_support
from . import test_code as code_support
from .test_messages import MessageFixture


class CodeBridgeFixture(message_support.BridgeOwnerFixture):
    def setUp(self):
        super().setUp()
        self.code_grants = {}
        template = next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write'))
        actors = []
        for identity, actions in (('human', ('publish', 'approve', 'fetched', 'read', 'inspect', 'outcome')),
                ('service', ('index', 'read', 'inspect', 'outcome'))):
            grants = {}
            for action in actions:
                contract = 'federation-code-' + action
                grant = copy.deepcopy(template)
                grant.update(ref=ref('code-' + identity + '-' + action), callerRef=ref(identity),
                    actorRef=ref(identity), contractId=contract)
                self.record['state']['grants'].append(grant)
                grants[contract] = grant['ref']
            self.code_grants[identity] = grants
            actors.append(LegacyCodeActor(canonical_bytes(ref(identity)),
                canonical_bytes(ref('transport' if identity == 'human' else 'legacy-service-transport')),
                'operator' if identity == 'human' else 'federation', canonical_bytes(grants)))
        self.code_actors = tuple(actors)
        self.js.messages[0].data = canonical_bytes(self.record)

    def open_code(self):
        return CodeStorageResource(OwnerBinding('hub-one','federation-code','task-one','code-channel',
            canonical_bytes(self.scope)), self.owner, repository='falcon', actors=self.native_actors,
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one', legacy_actors=self.code_actors)

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        self.native_actors = self.resource.actors
        await self.reply_service.close()
        patch('capability_owner.code_legacy.datetime', _Clock).start()
        patch('capability_owner.code_bridge_service.datetime', _Clock).start()
        for statement in Code.tables:
            self.store.db.execute(statement)
        self.resource = self.open_code()
        self.endpoint = self.open_endpoint()
        self.addAsyncCleanup(self.endpoint.close,timeout=None)

    def open_endpoint(self):
        return CodeBridgeService(self.service.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'),service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'),signing_seed=SEED)

    def item(self):
        return code_support.CodeFixture.value(self)['envelope']

    def code_request(self, action, value=None, *, operation='code-one', revision=1, identity=None):
        identity = identity or ('service' if action == 'index' else 'human')
        contract = 'federation-code-' + action
        payload = {'resourceRef':{**ref('task-one'),'revision':revision},'input':value or {}}
        if action not in ('read','inspect','outcome'):
            payload['attribution'] = 'operator' if identity == 'human' else 'federation'
        self.claims.update(operationId=operation,expectedVersion=revision,contractId=contract,
            transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            grantRef=self.code_grants[identity][contract],payload=payload,
            replySubject='_INBOX.code_bridge_000000001')
        return self.request()

    def verify_reply(self,response,raw,*,now=NOW):
        return verify_code_bridge_reply(response,raw,
            public_key=self.record['state']['issuers'][0]['publicKey'],service_identity_ref=ref('service'),
            service_instance_id='ingress-one',signing_key_ref=ref('issuer'),now=now)

    async def code_call(self,raw):
        return self.verify_reply(await self.endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject']),raw)

    def query(self,raw):
        claims = strict_loads(raw)['claims']
        return {'contractId':claims['contractId'],'operationId':claims['operationId'],
            'payloadDigest':payload_digest(claims['payload'])}


class CodeBridgeOwnerTests(CodeBridgeFixture,unittest.IsolatedAsyncioTestCase):
    async def test_publish_exact_id_outbox_original_reads_and_signed_replay(self):
        item = self.item()
        raw = self.code_request('publish',{'envelope':item})
        first = await self.code_call(raw)
        self.assertEqual(first['result']['id'],item['id'])
        self.assertEqual(await self.code_call(raw),first)
        row = self.store.q1('SELECT * FROM p_code_shares')
        self.assertEqual((row['id'],row['note'],row['sha'],row['files']),
            (item['id'],'Original code','a'*40,'one.py\ntwo.py'))
        for command in ('get','list','panel'):
            value = {'command':command}
            if command == 'get':value['id']=item['id']
            result = await self.code_call(self.code_request('read',value,operation='read-'+command))
            self.assertEqual(result,{'row':row} if command=='get' else {'rows':[
                {k:row[k] for k in ('id','repo','from_peer','author','ref','sha','stat','note','fetched','at')}
                | ({'sha':row['sha'][:12]} if command=='list' else {})]})
        self.assertEqual(self.store.q1('SELECT * FROM fed_outbox')['msg_id'],item['id'])
        self.assertEqual(self.store.q1('SELECT * FROM fed_audit')['msg_id'],item['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)

    async def test_lost_signed_reply_restart_recovers_exact_original_result_without_publication(self):
        raw = self.code_request('publish',{'envelope':self.item()})
        response = await self.endpoint.handle(raw,received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        original = self.verify_reply(response,raw)
        await self.endpoint.close(timeout=None)
        self.resource = self.open_code()
        self.endpoint = self.open_endpoint()
        self.addAsyncCleanup(self.endpoint.close,timeout=None)
        recovered = await self.code_call(self.code_request('outcome',self.query(raw),operation='recover'))
        self.assertEqual({key:recovered[key] for key in original},original)
        self.assertEqual(await self.code_call(raw),original)
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')),1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)

    async def test_signed_receipt_failure_rolls_back_original_code_outbox_audit_and_journal(self):
        raw=self.code_request('publish',{'envelope':self.item()})
        with patch.object(self.resource._journal,'_set',side_effect=RuntimeError('private fixture failure')):
            with self.assertRaises(ContractError):await self.code_call(raw)
        for table in ('p_code_shares','fed_outbox','fed_audit','fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM '+table),[])
        result=await self.code_call(raw)
        self.assertEqual(result['outcome'],'applied')
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)

    async def test_cas_conflict_retains_exact_outcome_and_adds_no_code_effect(self):
        await self.code_call(self.code_request('publish',{'envelope':self.item()}))
        raw = self.code_request('publish',{'envelope':self.item()},operation='stale')
        first = await self.code_call(raw)
        self.assertEqual((first['outcome'],first['result']),('conflict',None))
        self.assertEqual(await self.code_call(raw),first)
        recovered = await self.code_call(self.code_request('outcome',self.query(raw),operation='recover-conflict'))
        self.assertEqual({key:recovered[key] for key in first},first)
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')),1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)

    async def test_service_index_preserves_peer_author_untrusted_and_exact_route(self):
        self.owner.policy = policy(peers={'alice':{'trust':'approve'}})
        item=self.item();item.update({'from':'alice','node':'remote'})
        item['data'].update(author='remote/author',base='legacy-base-reference',ref='refs/agentmux/alice/feature')
        value={'envelope':item,'subject':'am.code.alice.'+item['rid'],'localNode':'mac'}
        result=await self.code_call(self.code_request('index',value))
        self.assertEqual(result['result']['outcome'],'delivered')
        row=self.store.q1('SELECT * FROM p_code_shares')
        self.assertEqual((row['id'],row['author'],row['untrusted'],row['base']),
            (item['id'],'remote/author',1,'legacy-base-reference'))
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'),[])
        for field,changed in (('subject','am.code.bob.'+item['rid']),('localNode','other')):
            with self.assertRaises(ContractError):
                await self.code_call(self.code_request('index',{**value,field:changed},operation='wrong-'+field,revision=2))

    async def test_held_operator_approval_requires_exact_envelope_and_current_policy(self):
        item=self.item();item.update({'from':'alice','node':'remote'})
        item['data'].update(author='remote/author',ref='refs/agentmux/alice/feature')
        subject='am.code.alice.'+item['rid']
        qid=ledger.quarantine_add(self.store,item,subject,'code','alice','held for review')
        value={'envelope':item,'subject':subject,'localNode':'mac','quarantineId':qid,'privileged':False}
        changed=copy.deepcopy(value);changed['envelope']['data']['note']='replacement'
        with self.assertRaises(ContractError):
            await self.code_call(self.code_request('approve',changed,operation='wrong-held'))
        result=await self.code_call(self.code_request('approve',value))
        self.assertEqual(result['result']['outcome'],'delivered')
        row=self.store.q1('SELECT * FROM p_code_shares')
        self.assertEqual((row['id'],row['note'],row['untrusted']),(item['id'],'Original code',1))
        self.owner.policy=policy(peers={'alice':{'trust':'deny'}})
        with self.assertRaises(ContractError):
            await self.code_call(self.code_request('approve',value,operation='now-denied',revision=2))
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')),1)

    async def test_fetched_timestamp_is_retained_across_replay_and_restart(self):
        item=self.item()
        await self.code_call(self.code_request('publish',{'envelope':item}))
        raw=self.code_request('fetched',{'id':item['id']},operation='fetched',revision=2)
        with patch('capability_owner.code.now',return_value='2026-10-17T12:00:00Z'):
            first=await self.code_call(raw)
        with patch('capability_owner.code.now',side_effect=AssertionError('duplicate fetched mutation')):
            self.assertEqual(await self.code_call(raw),first)
        self.resource=self.open_code()
        self.endpoint._resources['task-one']=self.resource
        recovered=await self.code_call(self.code_request('outcome',self.query(raw),operation='recover-fetched'))
        self.assertEqual({key:recovered[key] for key in first},first)
        self.assertEqual(first['result']['fetched'],'2026-10-17T12:00:00Z')

    async def test_current_original_grant_revocation_prevents_recovery(self):
        raw=self.code_request('publish',{'envelope':self.item()})
        await self.code_call(raw)
        self.claims.update(operationId='revoke-code-publish',contractId='identity-revoke',grantRef=ref('grant'),
            expectedVersion=2,payload={'authorityId':'authority-one',
                'targetRef':self.code_grants['human']['federation-code-publish']})
        receipt=strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
        with self.assertRaises(ContractError):
            await self.code_call(self.code_request('outcome',self.query(raw),operation='revoked-recovery'))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)

    async def test_wrong_actor_author_scope_and_grant_cannot_mutate(self):
        item=self.item();item['data']['author']='forged'
        with self.assertRaises(ContractError):
            await self.code_call(self.code_request('publish',{'envelope':item},operation='wrong-author'))
        self.code_request('publish',{'envelope':self.item()})
        original=copy.deepcopy(self.claims)
        for key,value in (('grantRef',ref('messages-write')),('scope',{**self.scope,'projectId':'other'}),
                ('transportRef',ref('legacy-service-transport'))):
            self.claims=copy.deepcopy(original);self.claims[key]=value
            with self.assertRaises(ContractError):await self.code_call(self.request())
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'),[])

    async def test_valid_authoritative_foreign_scope_cannot_reach_selected_owner(self):
        from unittest.mock import AsyncMock
        from identity.authority import AuthoritySnapshot
        raw=self.code_request('publish',{'envelope':self.item()})
        current=copy.deepcopy(self.record)
        foreign={**self.scope,'projectId':'other'}
        grant=next(g for g in current['state']['grants']
            if g['ref']==self.code_grants['human']['federation-code-publish'])
        grant['scope']=foreign
        member=copy.deepcopy(next(m for m in current['state']['memberships'] if m['identityRef']==ref('human')))
        member.update(ref=ref('foreign-code-member'),scope=foreign)
        current['state']['memberships'].append(member)
        with patch.object(self.service.reader,'current',AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current),1))):
            admitted=await self.service.ingress.admit(raw,cancellation_ref=ref('cancel'))
            self.assertEqual(admitted.decision.outcome,'allowed')
            self.assertEqual(strict_loads(admitted.envelope)['operation']['scope'],foreign)
            with self.assertRaises(ContractError):
                await self.resource.authorize_legacy(self.service.reader,admitted.envelope)
            with self.assertRaises(ContractError):await self.code_call(raw)
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'),[])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'),[])

    async def test_signed_reply_tamper_wrong_purpose_request_and_expiry_are_unconfirmed(self):
        raw=self.code_request('inspect')
        response=await self.endpoint.handle(raw,received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        self.assertEqual(self.verify_reply(response,raw)['resourceRef']['revision'],1)
        for field,value in (('purpose','agentmux-legacy-knowledge-response-v1'),('operationId','other')):
            forged=strict_loads(response);forged['claims'][field]=value
            forged['signature']=sign_claims(forged['claims'],SEED)
            with self.assertRaises(ContractError):self.verify_reply(canonical_bytes(forged),raw)
        forged=strict_loads(response);forged['claims']['result']={'resourceRef':ref('other')}
        with self.assertRaises(ContractError):self.verify_reply(canonical_bytes(forged),raw)
        with self.assertRaises(ContractError):self.verify_reply(response,raw,now=NOW+timedelta(seconds=5))

    async def test_bounded_read_refuses_complete_oversized_original_row(self):
        item=self.item()
        await self.code_call(self.code_request('publish',{'envelope':item}))
        self.store.db.execute('UPDATE p_code_shares SET note=?',('x'*1_000_001,))
        with self.assertRaises(ContractError):
            await self.code_call(self.code_request('read',{'command':'get','id':item['id']},operation='large-read'))
        self.assertEqual(self.store.q1('SELECT length(note) n FROM p_code_shares')['n'],1_000_001)

    async def test_cancelled_reply_keeps_original_owner_until_cleanup_joins(self):
        raw=self.code_request('publish',{'envelope':self.item()})
        entered,release=asyncio.Event(),asyncio.Event()
        original=self.owner.db
        async def held(function,*args,**kwargs):
            if function==self.resource._journal.commit:
                entered.set();await release.wait()
            return await original(function,*args,**kwargs)
        self.owner.db=held
        caller=asyncio.create_task(self.endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject']))
        try:
            await asyncio.wait_for(entered.wait(),2)
            caller.cancel()
            with self.assertRaises(asyncio.CancelledError):await caller
            with self.assertRaises(ContractError):await self.endpoint.close(timeout=.01)
            self.assertTrue(self.endpoint._workers)
        finally:
            release.set()
            await self.endpoint.close(timeout=None)
            await asyncio.gather(caller,return_exceptions=True)
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')),1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')),1)
