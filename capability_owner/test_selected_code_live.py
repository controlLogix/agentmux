"""Actual selected code factory retains its source across policy replacement."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import time
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.fed import envelope
from hub.fed.plugins.code import Code
from hub.store import Store
from identity.application_client import ApplicationClientKey, load_application_client
from identity.test_authority import ref
from identity.transitions import transition
from .code import CodeStorageResource
from .code_host import CodeStoreHost
from . import test_policy_selected_live as support


@unittest.skipUnless(os.environ.get('AMX_SELECTED_POLICY_LIVE')=='1','Coordinated selected policy live slot required')
class SelectedCodeFactoryLiveTests(support.SelectedPolicyLiveTests):
    def setUp(self):
        super().setUp()
        self.code = copy.deepcopy(self.knowledge)
        channel = self.code['channels'][0]
        channel['resourceRef'] = ref('code-one')
        channel['initialSource'] = None
        channel.pop('messageSources',None)
        self.code_grants = {'federation-code-'+action:ref('selected-code-'+action)
            for action in ('publish','fetched','approve','read','inspect','outcome')}
        channel['legacyActors'] = [{'identityRef':ref('human'),'transportRef':ref('selected-code-transport'),
            'caller':'operator','grants':copy.deepcopy(self.code_grants)}]
        self.value['storage']['code'] = self.code
        store=Store(self.code['source']['database']['path'])
        try:
            for statement in Code.tables:store.db.execute(statement)
        finally:
            store.db.close()

    def configure_broker_policies(self,policies,reads):
        super().configure_broker_policies(policies,reads)
        subject='amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.storage-owner.command'
        policies['application']['publish']['allow'].append(subject)

    def initial_authority(self):
        record=super().initial_authority()
        # Keep the same original file, but select only code so the actual code
        # source factory constructs CodeStoreHost rather than borrowing knowledge.
        self.value['storage'].pop('knowledge')
        self.value.pop('peerControl',None)
        state=record['state']
        template=copy.deepcopy(next(g for g in state['grants'] if g['ref']==ref('policy-set')))
        for contract,reference in self.code_grants.items():
            state['grants'].append({**copy.deepcopy(template),'ref':reference,'contractId':contract,
                'resourceId':'code-one'})
        key_path=self.directory/'application-client.key'
        key=load_application_client(key_path)
        material=strict_loads(key._material)
        material['codeCommands']={'authenticatedCaller':'operator',
            'subject':'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.storage-owner.command',
            'transportRef':ref('selected-code-transport'),'grantRefs':copy.deepcopy(self.code_grants),
            'resourceRef':ref('code-one'),'localPeer':self.code['localPeer'],'localNode':self.code['localNode'],
            'repository':{k:self.code['repository'][k] for k in ('localName','repositoryId')},
            'replyIssuerRef':ref('storage-issuer'),
            'replyIssuerPublicKey':support.base64.urlsafe_b64encode(bytes(
                support.SigningKey(self.receiver_seeds['storage']).verify_key)).decode().rstrip('='),
            'serviceIdentityRef':ref('storage-service'),'serviceInstanceId':'storage-instance'}
        extended=ApplicationClientKey(material)
        original=next(t for t in state['transports'] if t['ref']==material['transportRef'])
        transport={**copy.deepcopy(original),'ref':ref('selected-code-transport'),'publicKey':extended.public_key}
        proof={'purpose':'agentmux-enrollment-possession-v1','profileId':material['profileId'],
            'authorityId':material['authorityId'],'credential':transport}
        identity=next(i for i in state['identities'] if i['ref']==material['callerRef'])
        payload={'authorityId':material['authorityId'],'identity':copy.deepcopy(identity),'issuers':[],
            'transports':[{'record':transport,'proof':sign_claims(proof,extended._seed)}]}
        record['state']=transition(state,'identity-enroll',payload,hub_id='hub-one')
        key_path.write_bytes(extended._material)
        return record

    async def code_request(self,action,value,*,operation,revision=1):
        self.refresh_application_observation()
        payload={'resourceRef':{**ref('code-one'),'revision':revision},'input':value}
        if action not in ('read','inspect','outcome'):payload['attribution']='operator'
        expires=(datetime.now(timezone.utc)+timedelta(seconds=4)).isoformat().replace('+00:00','Z')
        return await asyncio.to_thread(self.session.code_command,contract_id='federation-code-'+action,
            operation_id=operation,payload=payload,expires_at=expires,deadline=time.monotonic()+3)

    async def retain_failure_diagnostic(self):
        # Keep only fixed categories and lifecycle states in this owned private
        # fixture. Never retain request bytes, credentials or arbitrary errors.
        import re
        def exception(error):
            rows=[]
            seen=set()
            while error is not None and id(error) not in seen and len(rows)<5:
                seen.add(id(error))
                message=str(error)
                rows.append({'class':type(error).__name__,'code':message if re.fullmatch(
                    r'[a-z_]{1,96}',message) else 'private_detail_omitted'})
                error=getattr(error,'cause',None) or getattr(error,'_cause',None) or error.__cause__
            return rows
        def task(original):
            if original is None:return None
            result={'done':original.done(),'cancelled':original.cancelled()}
            if original.done() and not original.cancelled():
                result['error']=exception(original.exception())
            return result
        session=self.session
        owner=session._owner
        source=self.selected._preconstructed_sources['code']
        transition=source._policy_transition
        diagnostic={'sessionFuture':task(getattr(session,'_command_future',None)),
            'nativeThreadAlive':session._thread.is_alive(),'sessionStopped':session._stopped,
            'ownerConnected':owner._connected,'ownerClosing':owner._closing,
            'clientConnected':owner._client.is_connected,'clientClosed':owner._client.is_closed,
            'exchange':task(owner._exchange_task),'subscriptions':len(owner._subscriptions),
            'source':{name:getattr(source,name) for name in ('_closed','_policy_generation',
                '_policy_paused','_policy_replacing','_policy_suspended')},
            'transitionUncertain':transition._uncertain is not None,
            'commitHandedOff':transition._commit_handed_off is not None,
            'originalTransitions':[task(original) for original in transition._operations.values()],
            'selectedPaused':self.selected._policy_change is not None}
        command=getattr(owner,'_command_request',None)
        if command is not None:
            claims=strict_loads(command)['claims']
            diagnostic['commandContract']=claims['contractId']
            diagnostic['commandExpired']=datetime.now(timezone.utc)>=datetime.fromisoformat(claims['expiresAt'])
        try:
            async with asyncio.timeout(2):
                current=await self.actual_policy.ledger.current()
            diagnostic['ledgerSequence']=current.sequence
        except Exception as error:
            diagnostic['ledgerError']=exception(error)
        path=self.directory/'selected-code-failure.json'
        path.write_bytes(canonical_bytes(diagnostic));path.chmod(0o600)
        print('Selected code private diagnostic: '+str(path))

    async def test_selected_code_owner_unshare_replacement_and_reshare_preserve_original(self):
        source=self.selected._preconstructed_sources['code']
        self.assertIs(type(source),CodeStoreHost)
        self.assertEqual(len(self.selected._message_stores),1)
        resources=[r for r in self.selected._resources if type(r) is CodeStorageResource]
        self.assertEqual(len(resources),1)
        resource=resources[0]
        self.assertIs(resource._store,source._store)
        import threading
        self.assertNotEqual(await source.db(threading.get_ident),threading.get_ident())
        self.assertEqual(await resource.read(1),canonical_bytes({'formatVersion':1,'source':None}))
        item=envelope.make('code','nick','mac',resource.repository_id,'*',{
            'ref':'refs/agentmux/nick/selected_feature','sha':'a'*40,'base':'b'*40,'files':['original.py'],
            'stat':'1 file','log':'Original selected source','note':'Retained code pointer',
            'slug':'selected_feature','author':'operator','remote':'example.invalid/falcon'})
        first=await self.code_request('publish',{'envelope':item},operation='selected-code-original')
        self.assertEqual(first['outcome'],'applied')
        self.assertEqual(first['result']['id'],item['id'])
        revision=first['resourceRef']['revision']
        original_bytes=await resource.read(revision)
        original_journal,original_base=resource._journal.binding,resource._journal._base
        original_store=source._store
        row=strict_loads(original_bytes)
        self.assertEqual((row['id'],row['files'],row['note']),(item['id'],'original.py','Retained code pointer'))
        payload={'resourceRef':ref('code-one'),'input':{'envelope':item},'attribution':'operator'}
        query={'contractId':'federation-code-publish','operationId':'selected-code-original',
            'payloadDigest':payload_digest(payload)}
        retained=await source.db(resource._journal.outcome,query['operationId'],query['payloadDigest'])
        self.assertEqual(retained['reply']['receiptRef'],first['receiptRef'])
        unshared=await self.request_hub('fed_unshare',{'repo':'falcon','operationId':'selected-code-unshare'})
        if not unshared['ok']:
            await self.retain_failure_diagnostic()
        self.assertTrue(unshared['ok'],unshared)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,1)
        with self.assertRaises(ContractError):await resource.read(revision)
        with self.assertRaises(Exception):
            await self.code_request('read',{'command':'get','id':item['id']},operation='unshared-code-read',revision=revision)
        original_call=getattr(self.session,'_command_future',None)
        if original_call is not None:
            with self.assertRaises(Exception):
                await asyncio.shield(asyncio.wrap_future(original_call))
        await self.selected.close(timeout=None)
        self.apps[-1]._identity=None
        await self.apps[-1].close()
        await self.start_selected()
        source=self.selected._preconstructed_sources['code']
        replacement=next(r for r in self.selected._resources if type(r) is CodeStorageResource)
        self.assertIs(type(source),CodeStoreHost)
        self.assertEqual(len(self.selected._message_stores),1)
        self.assertIsNot(source._store,original_store)
        self.assertEqual((replacement._journal.binding,replacement._journal._base),(original_journal,original_base))
        self.assertEqual(self.selected._startup_permits,{})
        with self.assertRaises(ContractError):await replacement.read(revision)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,1)
        reshared=await self.request_hub('fed_share',{'repo':'falcon','remote':'example.invalid/falcon',
            'peers':['*'],'operationId':'selected-code-reshare'})
        self.assertTrue(reshared['ok'],reshared)
        self.assertEqual((await self.actual_policy.ledger.current()).sequence,2)
        self.assertEqual(await replacement.read(revision),original_bytes)
        recovered=await self.code_request('outcome',query,operation='recover-selected-code',revision=revision)
        self.assertEqual(recovered['receiptRef'],first['receiptRef'])
        self.assertEqual(recovered['result'],first['result'])
        self.assertEqual(len(await source.db(source._store.q,'SELECT * FROM p_code_shares')),1)
        self.assertEqual(len(await source.db(source._store.q,'SELECT * FROM fed_outbox WHERE msg_id=?',(item['id'],))),1)
        self.path.write_bytes(self.path.read_bytes()+'\n# unapproved source replacement\n'.encode())
        with self.assertRaises(ContractError):await replacement.read(revision)
        self.success=True


# Reuse enrolled native owners and their cleanup, without rerunning the original
# knowledge/control exercise or any inherited unrelated task workflow.
for _name in dir(support.SelectedPolicyLiveTests):
    if _name.startswith('test_'):
        setattr(SelectedCodeFactoryLiveTests,_name,None)
