"""Real signed authority/custody with a controlled B command boundary."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from hub.nats_transport import new_client
from nats.aio.subscription import Subscription
from nats.errors import ConnectionClosedError
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.application_account import ApplicationAccountAuthority
from identity.test_authority import ref, SEED
from identity import test_application_account as account_support
from identity.transitions import transition
from native_security.secret_custody import ScopedSecretCustody, _resolved_binding
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED
from state_owner.task_service import TaskService
from capability_owner.test_secret_journal import SecretJournalTests
from .test_container import ContainerTests
from .container import ContainerObservation
from .container_programs import DELIVER
from .task_credentials import TaskCredentialOwner, TaskCredentialPolicy, _subject


class TaskCredentialTests(ContainerTests):
    live=True
    setUpClass=classmethod(SecretJournalTests.setUpClass.__func__)
    tearDownClass=classmethod(SecretJournalTests.tearDownClass.__func__)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        account=account_support.ApplicationAccountTests();account.setUp()
        self.account_seed=nkeys.encode_seed(bytes(range(32)),nkeys.PREFIX_BYTE_ACCOUNT)
        key=nkeys.from_seed(self.account_seed);self.account_public=key.public_key.decode();key.wipe()
        state=self.record['state'];other=account.record['state']
        other['applicationAccounts'][0]['accountPublicKey']=self.account_public
        for collection in ('identities','transports','memberships','secretReferences','applicationAccounts','grants'):
            state.setdefault(collection,[]);known={row['ref']['id'] for row in state[collection]}
            state[collection].extend(copy.deepcopy(row) for row in other[collection] if row['ref']['id'] not in known)
        def current(value):
            if type(value) is dict:
                for k,v in value.items():
                    if k=='issuedAt':value[k]=(datetime.now(timezone.utc)-timedelta(seconds=2)).isoformat().replace('+00:00','Z')
                    elif k in ('expiresAt','deadline'):value[k]=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat().replace('+00:00','Z')
                    else:current(v)
            elif type(value) is list:
                for v in value:current(v)
        current(state)
        grant=next(g for g in state['grants'] if g['ref']==ref('account-resolve-grant'))
        grant.update(actorRef=ref('administrator'),callerRef=ref('administrator'))
        for contract in ('task-credential-prepare','task-credential-deliver','task-credential-observe','task-credential-retire'):
            state['grants'].append({**copy.deepcopy(grant),'ref':ref(contract+'-grant'),
                'contractId':contract,'resourceId':'credential','scope':self.scope})
        state['grants'].append({**copy.deepcopy(grant),'ref':ref('worker-read-grant'),
            'actorRef':ref('worker'),'callerRef':ref('worker'),'contractId':'task-inspect',
            'resourceId':'task-one','scope':self.scope})
        state['issuers'].append({**copy.deepcopy(state['issuers'][0]),'ref':ref('consumer-issuer'),
            'identityRef':ref('consumer'),'instanceId':'consumer-instance'})
        self.sync()
        self.account_payload={**account.payload,'accountPublicKey':self.account_public}
        self.account_request=self.account_envelope()
        admin_root=self.path/'account-custody';admin_root.mkdir(mode=0o700)
        self.account_custody=ScopedSecretCustody(admin_root,self.service.reader)
        snapshot=await self.service.reader.current()
        self.account_custody._store.provision(_resolved_binding(snapshot,self.account_request,
            'nats-account-issuer',datetime.now(timezone.utc)),self.account_seed)
        root=self.path/'task-custody';root.mkdir(mode=0o700);self.custody_root=root
        binding=OwnerBinding('hub-one','task-credentials','credential','effect',canonical_bytes(self.scope))
        self.credential_js=FakeJetStream(self.policy);self.credential_js.config.subjects=[owner_subject(binding)]
        self.credential_ledger=OwnerLedger(self.credential_js,stream='OWNER',subject=owner_subject(binding),binding=binding,
            retention=self.policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        self.task_service=TaskService(self.owner,self.service.ingress,connection=None,service_identity_ref=ref('consumer'),
            service_instance_id='consumer-instance',signing_key_ref=ref('consumer-issuer'),signing_seed=SEED,
            requester_reply_prefix='_INBOX.task_consumer_00000001',account_public_key=self.account_public)
        self.credential_policy=TaskCredentialPolicy(canonical_bytes(ref('consumer')),'tls://127.0.0.1:4222','localhost',
            self.pem,'sha256:'+'a'*64,canonical_bytes(ref('application-account')),self.account_public,
            canonical_bytes(ref('issuer')),'_INBOX.task_consumer_00000001')
        self.credentials=self.make_credentials()

    def make_credentials(self):
        owner=TaskCredentialOwner(self.service.reader,self.credential_ledger,self.account_custody,self.adapter,
            self.task_service,policy=self.credential_policy,custody_root=self.custody_root,owner_identity_ref=ref('administrator'))
        self.addAsyncCleanup(owner.close)
        return owner

    def account_envelope(self):
        env=strict_loads(self.request('task-inspect',{'taskId':'task-one'}))
        env.update(contractId='identity-application-account-resolve',destinationServiceId='identity-owner',payload=self.account_payload)
        env['operation'].update(grantRef=ref('account-resolve-grant'),expectedVersion=0,taskId=None,
            payloadDigest=payload_digest(self.account_payload))
        claims=env['ingressAttestation']['claims'];claims.update(contractId=env['contractId'],operation=env['operation'],
            audience={'hubId':'hub-one','serviceId':'identity-owner'})
        env['ingressAttestation']['signature']=sign_claims(claims,SEED)
        return canonical_bytes(env)

    def phase(self,name,*,run=None,operation=None,**changes):
        payload={'credentialRef':ref('credential'),'runRef':run or self.run_ref}
        if name=='prepare':payload.update(taskReadGrantRef=ref('worker-read-grant'),taskApprovalRefs=[])
        payload.update(changes)
        return self.request('task-credential-'+name,payload,expected=len(self.credential_js.messages),operation=operation)

    async def ready(self,*,physical=False):
        self.admission,self.intent=await self.authorized();self.run_ref=strict_loads(self.admission.binding)['runRef']
        self.prepare_raw=self.phase('prepare')
        result=strict_loads(await self.credentials.prepare(self.prepare_raw,self.admission,
            task_inspection=self.inspection(),account_request=self.account_request))
        self.credential_record=result['record'];self.enrollment=result['enrollment']
        # The actual organization-admin transition checks the new key's proof.
        state=transition(self.record['state'],'identity-enroll',self.enrollment,hub_id='hub-one')
        self.record['state']=state;self.sync()
        if physical:await self.adapter.prepare(self.admission,task_inspection=self.inspection(),intent=self.intent)
        return result

    async def deliver(self):
        self.deliver_raw=self.phase('deliver')
        return await self.credentials.deliver(self.deliver_raw,self.admission,task_inspection=self.inspection(),
            account_request=self.account_request,intent=self.intent)

    async def test_finite_private_generation_actual_enrollment_and_current_original(self):
        result=await self.ready()
        self.assertEqual(result['record']['consumerRef'],ref('consumer'))
        self.assertEqual(result['record']['destinationRef'],ref('consumer'))
        private=self.credentials._private(self.credential_record)
        _,credential=self.credentials._decode(private,self.credential_record)
        claims=strict_loads(base64.urlsafe_b64decode(credential.jwt.split('.')[1]+'==='))
        self.assertEqual(claims['nats']['pub']['allow'],[_subject(self.credential_record)])
        self.assertEqual(claims['nats']['sub']['allow'],[self.credential_record['replySubject']])
        self.assertEqual(claims['nats']['subs'],1)
        self.assertNotIn(credential.seed.decode(),str(result))
        self.assertNotIn(credential.jwt,str(result))
        again=strict_loads(await self.credentials.prepare(self.prepare_raw,self.admission,
            task_inspection=self.inspection(),account_request=self.account_request))
        self.assertEqual(again,result);self.assertEqual(len(self.credential_js.messages),1)
        await self.credentials._current_generation(self.credential_record,self.admission,self.inspection(),self.account_request)
        for collection,reference in (('transports',self.credential_record['transportRef']),('grants',ref('worker-read-grant'))):
            item=next(x for x in self.record['state'][collection] if x['ref']==reference);item['status']='revoked';self.sync()
            with self.assertRaises(ContractError):
                await self.credentials._current_generation(self.credential_record,self.admission,self.inspection(),self.account_request)
            item['status']='active';self.sync()

    async def test_exact_delivery_is_once_and_observation_survives_restart(self):
        await self.ready(physical=True);await self.deliver()
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'delivery-intent')
        with self.assertRaisesRegex(ContractError,'^task_credential_delivery_already_attempted$'):await self.deliver()
        await self.credentials.close();self.credentials=self.make_credentials()
        observed=strict_loads(await self.credentials.observe(self.phase('observe')))
        self.assertEqual(observed['phase'],'delivered')
        self.assertEqual(observed['record'],self.credential_record)
        with self.assertRaisesRegex(ContractError,'^task_credential_physical_state_unresolved$'):
            await self.credentials.retire(self.phase('retire'))
        await self.adapter.stop(self.run_ref)
        retired=strict_loads(await self.credentials.retire(self.phase('retire')))
        self.assertEqual(retired['phase'],'retired')
        await self.adapter.cleanup(self.run_ref)

    async def test_lost_delivery_ack_is_uncertain_and_never_repeated(self):
        await self.ready(physical=True)
        self.engine.exec_fixed=AsyncMock(side_effect=ContractError('execution_engine_command_unknown'))
        with self.assertRaises(ContractError):await self.deliver()
        self.assertEqual(self.engine.exec_fixed.await_count,1)
        await self.credentials.close();self.credentials=self.make_credentials()
        observed=strict_loads(await self.credentials.observe(self.phase('observe')))
        self.assertEqual(observed['phase'],'uncertain')
        with self.assertRaisesRegex(ContractError,'^task_credential_delivery_already_attempted$'):await self.deliver()
        self.assertEqual(self.engine.exec_fixed.await_count,1)
        await self.adapter.stop(self.run_ref);await self.credentials.retire(self.phase('retire'))
        await self.adapter.cleanup(self.run_ref)

    async def test_wrong_owner_run_scope_and_generation_refuse_before_delivery(self):
        await self.ready(physical=True)
        for raw in (self.phase('deliver',run=ref('wrong-run')),
                self.phase('deliver',credentialRef=ref('wrong-credential')),
                self.request('task-credential-deliver',{'credentialRef':ref('credential'),'runRef':self.run_ref},
                    caller='human',expected=1)):
            with self.assertRaises(ContractError):
                await self.credentials.deliver(raw,self.admission,task_inspection=self.inspection(),
                    account_request=self.account_request,intent=self.intent)
        self.assertEqual(self.engine.exec_fixed.await_count,1) # supervisor HEALTH in prepare
        state=self.credentials._history(await self.credential_ledger.current())
        self.assertEqual(state['phase'],'prepared')
        changed=copy.deepcopy(self.credential_record);changed['generationRef']=ref('foreign-generation')
        with self.assertRaises(ContractError):self.credentials._private(changed)
        await self.adapter.stop(self.run_ref);await self.adapter.cleanup(self.run_ref)

    async def test_expired_original_and_offline_authority_never_deliver(self):
        await self.ready(physical=True)
        grant=next(g for g in self.record['state']['grants'] if g['contractId']=='capability-process-start')
        grant['status']='revoked';self.sync()
        with self.assertRaises(ContractError):await self.deliver()
        grant['status']='active';self.sync()
        with patch.object(self.service.reader,'current',AsyncMock(side_effect=ContractError('authority_offline'))):
            with self.assertRaisesRegex(ContractError,'^authority_offline$'):await self.deliver()
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'prepared')
        await self.adapter.stop(self.run_ref);await self.adapter.cleanup(self.run_ref)


    async def test_rejected_intent_can_retire_only_exact_terminal_claim(self):
        await self.ready(physical=True)
        with patch.object(self.credential_ledger,'append',AsyncMock(side_effect=ContractError('owner_append_rejected'))):
            with self.assertRaisesRegex(ContractError,'^owner_append_rejected$'):
                await self.deliver()
        state=self.credentials._history(await self.credential_ledger.current())
        self.assertEqual(state['phase'],'prepared')
        self.assertFalse(self.credentials._clients or self.credentials._handlers or self.credentials._proofs)
        self.assertFalse(next(iter(self.adapter._runs.values())).get('private_attempted'))
        # A private claim is not permission to retire a still-live original.
        with self.assertRaises(ContractError):await self.credentials.retire(self.phase('retire'))
        self.assertEqual((await self.adapter.stop(self.run_ref)).status,'terminal')
        try:
            retired=strict_loads(await self.credentials.retire(self.phase('retire')))
            self.assertEqual(retired['phase'],'retired')
        finally:await self.adapter.cleanup(self.run_ref)

    async def rejected_claim(self):
        await self.ready(physical=True)
        with patch.object(self.credential_ledger,'append',AsyncMock(side_effect=ContractError('owner_commit_uncertain'))):
            with self.assertRaisesRegex(ContractError,'^owner_commit_uncertain$'):await self.deliver()
        with self.credentials._store.access(self.credential_record['generationRef']) as directory:
            private=tuple(self.credentials._store.read(directory,name)
                for name in ('assignment.json','credential.json','delivery.json'))
        claim=strict_loads(private[-1])
        self.assertEqual(claim['resourceRef'],strict_loads((await self.adapter.observe(self.run_ref)).resource_ref))
        self.assertEqual(claim['generationRef'],self.credential_record['generationRef'])
        self.assertEqual(claim['operation'],strict_loads(self.deliver_raw)['operation'])
        self.assertFalse(next(iter(self.adapter._runs.values())).get('private_attempted'))
        return private

    async def test_claim_reopen_retirement_retains_evidence_after_original_revocation(self):
        private=await self.rejected_claim()
        task_history=tuple(item.record for item in (await self.owner._ledger.current()).records)
        await self.credentials.close();self.credentials=self.make_credentials()
        with self.assertRaisesRegex(ContractError,'^task_credential_delivery_uncertain$'):await self.deliver()
        grant=next(g for g in self.record['state']['grants'] if g['contractId']=='capability-process-start')
        grant['status']='revoked';self.sync()
        self.assertEqual((await self.adapter.stop(self.run_ref)).status,'terminal')
        release=asyncio.Event();proof=asyncio.create_task(release.wait());self.credentials._proofs.add(proof)
        try:
            with self.assertRaisesRegex(ContractError,'^task_credential_users_not_joined$'):
                await self.credentials.retire(self.phase('retire'))
        finally:
            release.set();await proof;self.credentials._proofs.discard(proof)
        retired=strict_loads(await self.credentials.retire(self.phase('retire')))
        self.assertEqual(retired['phase'],'retired')
        self.assertEqual(retired['record'],self.credential_record)
        with self.credentials._store.access(self.credential_record['generationRef']) as directory:
            after=tuple(self.credentials._store.read(directory,name)
                for name in ('assignment.json','credential.json','delivery.json'))
        self.assertTrue(after==private,'Retirement changed private generation or original claim')
        self.assertTrue(tuple(item.record for item in (await self.owner._ledger.current()).records)==task_history,
            'Retirement changed task reservation or execution authority')
        again=await self.credentials.retire(self.phase('retire'))
        self.assertEqual(strict_loads(again),retired)
        self.assertEqual((await self.credential_ledger.current()).sequence,2)
        await self.adapter.cleanup(self.run_ref)

    async def test_claim_retirement_refuses_unknown_missing_or_replaced_resource(self):
        private=await self.rejected_claim();resource=strict_loads(private[-1])['resourceRef']
        with self.assertRaisesRegex(ContractError,'^task_credential_physical_state_unresolved$'):
            await self.credentials.retire(self.phase('retire'))
        changed={**resource,'containerId':'d'*64}
        observations=[ContainerObservation(canonical_bytes(self.run_ref),status,resource_ref=canonical_bytes(resource))
            for status in ('running','pending','unknown')]
        observations.extend((ContainerObservation(canonical_bytes(self.run_ref),'terminal'),
            ContainerObservation(canonical_bytes(self.run_ref),'terminal',resource_ref=canonical_bytes(changed))))
        for observed in observations:
            with self.subTest(status=observed.status),patch.object(self.adapter,'observe',AsyncMock(return_value=observed)):
                with self.assertRaisesRegex(ContractError,'^task_credential_physical_state_unresolved$'):
                    await self.credentials.retire(self.phase('retire'))
        with patch.object(self.engine,'find',AsyncMock(return_value=None)):
            with self.assertRaisesRegex(ContractError,'^task_credential_physical_state_unresolved$'):
                await self.credentials.retire(self.phase('retire'))
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'prepared')
        await self.adapter.stop(self.run_ref);await self.credentials.retire(self.phase('retire'))
        await self.adapter.cleanup(self.run_ref)

    async def test_claim_retirement_refuses_changed_original_metadata(self):
        private=await self.rejected_claim();claim=strict_loads(private[-1])
        await self.adapter.stop(self.run_ref)
        changes=[('generationRef',ref('foreign-generation')),('runRef',ref('foreign-run'))]
        candidates=[]
        for key,value in changes:
            changed=copy.deepcopy(claim);changed[key]=value;candidates.append(changed)
        for key,value in (('runRef',ref('foreign-run')),('bindingDigest','sha256:'+'0'*64)):
            changed=copy.deepcopy(claim);changed['resourceRef'][key]=value;candidates.append(changed)
        for key,value in (('expectedVersion',0),('operationId',self.credential_record['prepareOperationId']),
                ('effectiveActorRef',ref('consumer')),('payloadDigest','sha256:'+'0'*64),
                ('scope',{**self.scope,'projectId':'foreign-project'}),
                ('caller',{'principalId':'administrator','kind':'human','authenticatedIdentityRef':ref('administrator')})):
            changed=copy.deepcopy(claim);changed['operation'][key]=value;candidates.append(changed)
        extra=copy.deepcopy(claim);extra['extra']=True;candidates.append(extra)
        original_read=self.credentials._store.read
        for index,candidate in enumerate(candidates):
            def read(directory,name):
                return canonical_bytes(candidate) if name=='delivery.json' else original_read(directory,name)
            with self.subTest(case=index),patch.object(self.credentials._store,'read',side_effect=read):
                with self.assertRaisesRegex(ContractError,'^task_credential_claim_mismatch$'):
                    await self.credentials.retire(self.phase('retire'))
        self.assertEqual((await self.credential_ledger.current()).sequence,1)
        await self.credentials.retire(self.phase('retire'));await self.adapter.cleanup(self.run_ref)

    async def test_pending_subscription_alone_keeps_claim_retirement_refused(self):
        await self.rejected_claim();await self.adapter.stop(self.run_ref)
        client=new_client();await client.close()
        release=asyncio.Event();worker=asyncio.create_task(release.wait())
        subscription=Subscription(client,id=1,subject='retained-task-consumer')
        subscription._wait_for_msgs_task=worker
        self.credentials._subscriptions.append(subscription)
        self.assertFalse(self.credentials._clients or self.credentials._handlers or self.credentials._proofs)
        try:
            with self.assertRaisesRegex(ContractError,'^task_credential_users_not_joined$'):
                await self.credentials.retire(self.phase('retire'))
            self.assertEqual(self.credentials._history(await self.credential_ledger.current())['phase'],'prepared')
            release.set();await worker;await self.credentials._cleanup_users()
            self.assertEqual(strict_loads(await self.credentials.retire(self.phase('retire')))['phase'],'retired')
        finally:
            release.set();await worker;await self.credentials._cleanup_users()
            await self.adapter.cleanup(self.run_ref)

    async def test_stale_intent_refuses_before_private_claim(self):
        await self.ready(physical=True)
        payload={'credentialRef':ref('credential'),'runRef':self.run_ref}
        for raw in (self.request('task-credential-deliver',payload,expected=0,operation='stale-delivery'),
                self.request('task-credential-deliver',payload,expected=1,
                    operation=strict_loads(self.prepare_raw)['operation']['operationId'])):
            with self.assertRaises(ContractError):
                await self.credentials.deliver(raw,self.admission,task_inspection=self.inspection(),
                    account_request=self.account_request,intent=self.intent)
        with self.credentials._store.access(self.credential_record['generationRef']) as directory:
            self.assertIsNone(self.credentials._store.read(directory,'delivery.json'))
        self.assertFalse(next(iter(self.adapter._runs.values())).get('private_attempted'))
        await self.adapter.stop(self.run_ref);await self.credentials.retire(self.phase('retire'))
        await self.adapter.cleanup(self.run_ref)

    async def test_retired_replay_rechecks_current_service_before_disclosure(self):
        await self.rejected_claim();await self.adapter.stop(self.run_ref)
        await self.credentials.retire(self.phase('retire'))
        current=self.credential_ledger.current
        async def revoke_during_read():
            result=await current()
            grant=next(g for g in self.record['state']['grants'] if g['contractId']=='task-credential-retire')
            grant['status']='revoked';self.sync()
            return result
        with patch.object(self.credential_ledger,'current',side_effect=revoke_during_read):
            with self.assertRaisesRegex(ContractError,'^task_credential_not_authorized$'):
                await self.credentials.retire(self.phase('retire'))
        self.assertEqual((await current()).sequence,2)
        await self.adapter.cleanup(self.run_ref)

    async def observer_loss_keeps_delivery(self,mode):
        await self.ready(physical=True)
        entered,release=asyncio.Event(),asyncio.Event();invocations=[]
        async def held(container,uid,program,*,data=None):
            self.assertEqual(program,DELIVER)
            invocations.append((container,uid));entered.set();await release.wait()
            return b''
        original_exec=self.engine.exec_fixed;self.engine.exec_fixed=held
        observer=asyncio.create_task(self.deliver())
        retry=None;original_c=original_b=None
        try:
            await asyncio.wait_for(entered.wait(),5)
            self.assertEqual(len(self.credentials._jobs),1);self.assertEqual(len(self.adapter._jobs),1)
            original_c=next(iter(self.credentials._jobs));original_b=next(iter(self.adapter._jobs))
            with self.credentials._store.access(self.credential_record['generationRef']) as directory:
                claim=self.credentials._store.read(directory,'delivery.json')
            if mode=='cancel':
                observer.cancel()
                with self.assertRaises(asyncio.CancelledError):await observer
            else:
                with self.assertRaises(TimeoutError):await asyncio.wait_for(observer,.01)
            self.assertIn(original_c,self.credentials._jobs);self.assertIn(original_b,self.adapter._jobs)
            self.assertFalse(original_c.done() or original_b.done())
            retry=asyncio.create_task(self.deliver())
            await asyncio.sleep(0)
            self.assertEqual(len(invocations),1)
            self.assertIn(original_c,self.credentials._jobs);self.assertIn(original_b,self.adapter._jobs)
            release.set();await original_c;await original_b
            with self.assertRaisesRegex(ContractError,'^task_credential_delivery_already_attempted$'):await retry
            observed=strict_loads(await self.credentials.observe(self.phase('observe')))
            self.assertEqual(observed['phase'],'delivered')
            self.assertEqual(observed['record'],self.credential_record)
            self.assertEqual(len(invocations),1)
            with self.credentials._store.access(self.credential_record['generationRef']) as directory:
                self.assertTrue(self.credentials._store.read(directory,'delivery.json')==claim,
                    'Observer loss replaced the retained claim')
            self.assertFalse(self.credentials._jobs or self.adapter._jobs)
        finally:
            release.set()
            for original in (original_c,original_b,retry,observer):
                if original is not None:await asyncio.gather(original,return_exceptions=True)
            self.engine.exec_fixed=original_exec
            await self.adapter.stop(self.run_ref)
            await self.adapter.cleanup(self.run_ref)

    async def test_cancelled_delivery_observer_keeps_exact_original(self):
        await self.observer_loss_keeps_delivery('cancel')

    async def test_timed_out_delivery_observer_keeps_exact_original(self):
        await self.observer_loss_keeps_delivery('timeout')

    async def test_closed_connection_unsubscribe_still_joins_handlers_and_proofs(self):
        client=new_client();await client.close()
        subscription=Subscription(client,id=1,subject='closed-task-consumer')
        with self.assertRaises(ConnectionClosedError):await subscription.unsubscribe()
        release=asyncio.Event()
        handler=asyncio.create_task(release.wait());proof=asyncio.create_task(release.wait())
        self.credentials._handlers.add(handler);self.credentials._proofs.add(proof)
        self.credentials._subscriptions.append(subscription);self.credentials._clients.append(client)
        asyncio.get_running_loop().call_later(.01,release.set)
        await self.credentials._cleanup_users()
        self.assertTrue(handler.done() and proof.done())
        self.assertFalse(self.credentials._clients or self.credentials._subscriptions)
        self.credentials._handlers.discard(handler);self.credentials._proofs.discard(proof)

    async def test_cleanup_failure_retains_original_and_joins_other_clients(self):
        first,second=object(),object();self.credentials._clients.extend((first,second))
        closer=AsyncMock(side_effect=(ContractError('integration_operator_cleanup_unknown'),None))
        with patch('execution_owner.task_credentials._close_client',closer):
            with self.assertRaisesRegex(ContractError,'^task_credential_users_not_joined$'):
                await self.credentials._cleanup_users()
        self.assertEqual(closer.await_count,2);self.assertEqual(self.credentials._clients,[first])
        with patch('execution_owner.task_credentials._close_client',AsyncMock()):
            await self.credentials._cleanup_users()
        self.assertFalse(self.credentials._clients)

    async def test_original_expiry_and_online_generation_retirement_do_not_renew(self):
        await self.ready(physical=True)
        expired=replace(self.admission,valid_until=datetime.now(timezone.utc)-timedelta(seconds=1))
        with self.assertRaisesRegex(ContractError,'^execution_admission_expired$'):
            await self.credentials.deliver(self.phase('deliver'),expired,task_inspection=self.inspection(),
                account_request=self.account_request,intent=self.intent)
        await self.deliver()
        original_grant=next(g for g in self.record['state']['grants'] if g['contractId']=='capability-process-start')
        original_grant['status']='revoked';self.sync()
        # Current service completion survives loss of the human start grant.
        await self.credentials.observe(self.phase('observe'))
        with self.assertRaises(ContractError):
            await self.credentials.inspect_task(self.deliver_raw,self.admission,task_inspection=self.inspection(),
                account_request=self.account_request,intent=self.intent)
        await self.adapter.stop(self.run_ref);await self.credentials.retire(self.phase('retire'))
        with self.assertRaises(ContractError):
            await self.credentials.prepare(self.prepare_raw,self.admission,task_inspection=self.inspection(),
                account_request=self.account_request)
        await self.adapter.cleanup(self.run_ref)

    async def test_policy_requires_actual_prefixed_pin_and_fixed_consumer(self):
        for value in ('a'*64,'sha256:'+'A'*64,'sha256:'+'a'*63):
            with self.assertRaisesRegex(ContractError,'^task_credential_policy_invalid$'):
                replace(self.credential_policy,leaf_certificate_sha256=value)
        self.assertEqual(replace(self.credential_policy).pin(),self.credential_policy.pin())


for _name in dir(ContainerTests):
    if _name.startswith('test_') and _name not in vars(TaskCredentialTests):setattr(TaskCredentialTests,_name,None)
