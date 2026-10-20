"""Actual native provider delivery evidence over the accepted execution owner."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.capability_service import evaluate_capability_service_request
from identity.test_authority import ref, SEED
from identity.test_native_bridge import native_row, HOST_SEED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream, CREATED
from execution_owner.retained import RetainedExecutionOwner
from execution_owner.container import RetainedContainerIntent
from identity.execution_evidence import NativeExecutionEvidence
from execution_owner.test_retained import RetainedExecutionTests


def stamp(value):return value.isoformat(timespec='microseconds').replace('+00:00','Z')


class ProcessNativeDeliveryTests(RetainedExecutionTests):
    async def admin(self,contract,payload):
        snapshot=await self.service.reader.current();now=datetime.now(timezone.utc)
        claims={'purpose':'agentmux-client-possession-v1','hubId':'hub-one','profileId':'profile-one',
            'authorityId':'authority-one','transportRef':ref('administrator-transport'),
            'grantRef':ref('process-admin-'+contract),'operationId':'admin-'+contract+'-'+str(snapshot.sequence),
            'expectedVersion':snapshot.sequence,'contractId':contract,'payload':payload,'approvalRefs':[],
            'issuedAt':stamp(now),'expiresAt':stamp(now+timedelta(seconds=30))}
        return strict_loads(await self.service.handle(canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
            'signature':sign_claims(claims,bytes(reversed(SEED)))})))

    async def delivery(self,source,row,authority_ref,request_id,*,binding_id='process-start-binding'):
        now=datetime.now(timezone.utc)
        inp={'operation':strict_loads(source)['operation'],'operationAuthorityRef':authority_ref,
            'bindingId':binding_id,'contractId':strict_loads(source)['contractId'],
            'serviceRequestId':request_id,'serviceReplySubject':'_INBOX.abcdefghijklmnop',
            'payload':strict_loads(source)['payload'],'originalEnvelopeBytes':base64.b64encode(source).decode()}
        claims={'purpose':'agentmux-native-authority-request-v1','requestId':'native-process-request',
            'method':'prepare-domain-call','profileId':'profile-one','hubId':'hub-one','authorityId':'authority-one',
            'owner':row['owner'],'signingKeyRef':ref('host-transport'),'issuedAt':stamp(now),
            'expiresAt':stamp(now+timedelta(seconds=5)),'replySubject':'_INBOX.abcdefghijklmnop','input':inp}
        request={'schemaVersion':'1.0.0','algorithm':'Ed25519','canonicalization':'RFC8785-JCS-UTF8',
            'claims':claims,'signature':sign_claims(claims,HOST_SEED)}
        response=strict_loads(await self.service.native.handle(canonical_bytes(request)))
        result=response['claims']['result'];raw=base64.b64decode(result['envelopeBytes'])
        wrapper=base64.b64decode(result['serviceRequestBytes'])
        from identity.capability_routes import CAPABILITY_DESTINATIONS
        decision=evaluate_capability_service_request(await self.service.reader.current(),wrapper,
            service_id=CAPABILITY_DESTINATIONS[strict_loads(source)['contractId']],now=datetime.now(timezone.utc))
        self.assertEqual(decision.outcome,'allowed')
        return raw,wrapper

    def install_native_policy(self,run_id):
        state=self.record['state'];now=datetime.now(timezone.utc)
        for name,kind in (('host','service'),('plugin','plugin')):
            if any(item['ref']==ref(name) for item in state['identities']):continue
            state['identities'].append({'ref':ref(name),'status':'active','kind':kind,
                'principalId':name+'-one','externalIdentity':None})
        if not any(item['ref']==ref('host-transport') for item in state['transports']):state['transports'].append({**copy.deepcopy(state['transports'][0]),'ref':ref('host-transport'),
            'identityRef':ref('host'),'publicKey':base64.urlsafe_b64encode(bytes(SigningKey(HOST_SEED).verify_key)).decode().rstrip('=')})
        if not any(item['ref']==ref('process-host-member') for item in state['memberships']):state['memberships'].append({'ref':ref('process-host-member'),'identityRef':ref('host'),
            'scope':self.scope,'status':'active'})
        org={'organizationId':'org-one','projectId':None,'workspaceId':None}
        if not any(item['ref']==ref('process-admin-org') for item in state['memberships']):state['memberships'].append({'ref':ref('process-admin-org'),'identityRef':ref('administrator'),'scope':org,'status':'active'})
        template=next(g for g in state['grants'] if g['ref']==ref('task-credential-observe-grant'))
        for contract in ('identity-native-instance-set','identity-enroll','identity-revoke','identity-grant-set'):
            if any(item['ref']==ref('process-admin-'+contract) for item in state['grants']):continue
            state['grants'].append({**copy.deepcopy(template),'ref':ref('process-admin-'+contract),
                'contractId':contract,'resourceId':'authority-one','scope':org})
        if not any(item['ref']==ref('process-host-prepare') for item in state['grants']):state['grants'].append({**copy.deepcopy(template),'ref':ref('process-host-prepare'),
            'callerRef':ref('host'),'actorRef':ref('host'),'contractId':'native-authority-prepare-domain-call','resourceId':'plugin-one'})
        for grant in state['grants']:
            if grant['ref'] in (ref('execution-run-record-grant'),ref('execution-run-observe-grant')):grant['resourceId']=run_id
        self.sync()
        row=native_row();facts=row['facts']
        times={'issuedAt':stamp(now-timedelta(seconds=1)),'expiresAt':stamp(now+timedelta(minutes=5))}
        facts['grant'].update(scope=copy.deepcopy(self.scope),actions=['start'],resourceIds=['executor'],**times)
        facts['policy'].update(scope=copy.deepcopy(self.scope),**times)
        facts['policy']['decisions']=[{'access':{'action':'start','resourceClass':'process','resourceId':'executor'},'outcome':'allow'}]
        facts['domainBindings']=[{'id':'process-start-binding','contractId':'capability-process-start',
            'action':'start','resourceClass':'process','resourceIds':['executor']}]
        return row

    async def prepare_native_original(self, *, native=True, start=True):
        await self.retained_owner()
        source=self.original_start;request_id='request_'+'c'*64
        op_id='downstream_'+hashlib.sha256((strict_loads(source)['operation']['operationId']+'\0'+request_id).encode()).hexdigest()
        identity={'format':'agentmux-execution-run-reference-v1','ownerHubId':'hub-one',
            'scope':self.scope,'executorId':'executor','operationId':op_id}
        run_id='execution-'+payload_digest(identity).split(':',1)[1]
        row=self.install_native_policy(run_id)
        enrolled=await self.admin('identity-native-instance-set',{'authorityId':'authority-one','record':row,'previousRef':None})
        self.assertEqual(enrolled['claims']['receipt']['decision'],'allowed')
        authority_ref=ref('authority-one');authority_ref['revision']=(await self.service.reader.current()).sequence
        raw,wrapper=await self.delivery(source,row,authority_ref,request_id)
        evidence=NativeExecutionEvidence(wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin') if native else None
        envelope=strict_loads(raw);self.assertEqual(envelope['operation']['operationId'],op_id)
        self.assertEqual(envelope['operation']['deadline'],strict_loads(source)['operation']['deadline'])
        b=OwnerBinding('hub-one','execution',run_id,'attempt',canonical_bytes(self.scope))
        self.execution_js=FakeJetStream(self.policy);self.execution_js.config.subjects=[owner_subject(b)]
        self.execution_ledger=OwnerLedger(self.execution_js,stream='OWNER',subject=owner_subject(b),binding=b,
            retention=self.policy,stream_identity=StreamIdentity(CREATED,0),require_completion_budget=True)
        execution=RetainedExecutionOwner(self.service.reader,self.execution_ledger,self.plans,self.adapter,self.credentials,self.signer)
        self.execution=execution;self.addAsyncCleanup(execution.close)
        self.run=strict_loads((await self.plans.admit_start(raw,task_inspection=self.inspection(),native_evidence=evidence)).binding)
        if not start:
            expiry=datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt'])
            return {'execution':execution,'raw':raw,'wrapper':wrapper,'evidence':evidence,
                'source':source,'row':row,'authority_ref':authority_ref,'request_id':request_id,
                'public':None,'first':None,'expiry':expiry,
                'metadata':{'businessDeadline':envelope['operation']['deadline'],'deliveryExpiry':stamp(expiry)}}
        await execution.start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        public=strict_loads(await execution.enrollment(await self.observe_command()))
        first=self.execution_js.messages[0].data
        expiry=datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt'])
        metadata={'businessDeadline':envelope['operation']['deadline'],'deliveryExpiry':stamp(expiry),
            'firstAdmissionEnd':strict_loads(first)['state']['admissionEnd'],
            'credentialExpiresUnix':public['record']['expiresUnix']}
        return {'execution':execution,'raw':raw,'wrapper':wrapper,'evidence':evidence,
            'source':source,'row':row,'authority_ref':authority_ref,'request_id':request_id,
            'public':public,'first':first,'expiry':expiry,'metadata':metadata}

    async def delivery_case(self, *, native):
        case=await self.prepare_native_original(native=native)
        execution,raw,evidence,source,row,authority_ref,request_id,public,first,expiry,metadata=(case[key] for key in
            ('execution','raw','evidence','source','row','authority_ref','request_id','public','first','expiry','metadata'))
        envelope=strict_loads(raw)
        if not native:
            self.assertNotIn('nativeBinding',strict_loads(first)['state'])
        await asyncio.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+0.1)
        enrollment=await self.admin('identity-enroll',public['enrollment'])
        self.assertEqual(enrollment['claims']['receipt']['decision'],'allowed')
        if native:
            self.assertGreater(public['record']['expiresUnix'],expiry.timestamp())
            self.assertLessEqual(public['record']['expiresUnix'],datetime.fromisoformat(strict_loads(first)['state']['admissionEnd']).timestamp())
        failures=[]
        try:await execution.dispatch(raw,task_inspection=self.inspection(),native_evidence=evidence)
        except ContractError as exc:failures.append('preserved-original:'+str(exc))
        fresh,fresh_wrapper=await self.delivery(source,row,authority_ref,request_id)
        self.assertEqual(strict_loads(fresh)['operation'],envelope['operation'])
        self.assertEqual(strict_loads(fresh)['payload'],envelope['payload'])
        self.assertNotEqual(fresh,raw)
        with self.assertRaisesRegex(ContractError,'execution_original_conflict'):
            await execution.dispatch(fresh,task_inspection=self.inspection())
        if native:
            self.assertEqual(failures,['preserved-original:capability_service_expired'])
            self.assertEqual(self.commands,[])
            current=NativeExecutionEvidence(fresh_wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')
            replay=await execution.start(raw,task_inspection=self.inspection(),native_evidence=current)
            self.assertEqual(strict_loads(replay)['step'],'pending-enrollment')
            prepare=self.adapter.prepare
            async def checkpoint(*args,**kwargs):
                await prepare(*args,**kwargs)
                raise ContractError('focused_native_boundary')
            self.adapter.prepare=checkpoint
            try:
                with self.assertRaisesRegex(ContractError,'focused_native_boundary'):
                    await execution.dispatch(raw,task_inspection=self.inspection(),native_evidence=current)
            finally:self.adapter.prepare=prepare
            self.assertEqual(self.commands.count('create'),1)
            first_state=strict_loads(first)['state']
            _,private_wrapper=await self.delivery(source,row,authority_ref,request_id)
            current=NativeExecutionEvidence(private_wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin')
            fresh_admission=await self.plans.admit_start(raw,task_inspection=self.inspection(),
                retained_binding=canonical_bytes(first_state['executionBinding']),native_evidence=current,
                retained_native_binding=canonical_bytes(first_state['nativeBinding']))
        else:
            self.assertEqual(failures,['preserved-original:execution_admission_expired'])
            fresh_admission=await self.plans.admit_start(fresh,task_inspection=self.inspection(),
                retained_binding=canonical_bytes(strict_loads(first)['state']['executionBinding']))
        cancellation=self.run['originalOperation']['cancellationRef']
        delivery=await self.signer.credential('deliver',self.run,len(self.credential_js.messages),cancellation)
        if native:
            await self.credentials.deliver(delivery,fresh_admission,task_inspection=self.inspection(),
                account_request=await self.signer.account(cancellation),
                intent=RetainedContainerIntent(self.execution_ledger,fresh_admission.binding))
            self.assertEqual(len(self.credential_js.messages),2)
        else:
            with self.assertRaisesRegex(ContractError,'task_credential_expired'):
                await self.credentials.deliver(delivery,fresh_admission,task_inspection=self.inspection(),
                    account_request=await self.signer.account(cancellation),
                    intent=RetainedContainerIntent(self.execution_ledger,fresh_admission.binding))
            self.assertEqual(len(self.credential_js.messages),1)
            self.assertEqual(self.commands,[])
        self.assertEqual(self.execution_js.messages[0].data,first)
        await execution.cancel(self.cancel_command())
        await execution.retire(await self.observe_command())
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['record'],public['record'])
        print('Actual native delivery boundaries: '+str(metadata))

    async def test_actual_native_delivery_expiry_cannot_resume_live_business_original(self):
        await self.delivery_case(native=True)

    async def test_legacy_native_original_and_expired_generation_cannot_be_upgraded(self):
        await self.delivery_case(native=False)

    async def test_admitted_completion_is_not_public_ingress_after_delivery_expiry(self):
        case=await self.prepare_native_original(start=False)
        raw,evidence=case['raw'],case['evidence']
        admission=await self.plans.admit_start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        await asyncio.sleep(max(0,(case['expiry']-datetime.now(timezone.utc)).total_seconds())+0.1)
        for owner,method in ((self.plans,'admit_start'),(case['execution'],'start'),(case['execution'],'dispatch')):
            with self.assertRaises(ContractError):
                await getattr(owner,method)(raw,task_inspection=self.inspection(),native_evidence=admission._native_evidence)
        with self.assertRaisesRegex(ContractError,'capability_service_expired'):
            await self.plans.admit_start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        current=await admission.recheck(self.inspection())
        self.assertEqual(current.binding,admission.binding)
        self.assertLessEqual(current.valid_until,admission.valid_until)
        self.assertEqual(self.commands,[])

    async def completion_revocation_case(self, *, native):
        case=await self.prepare_native_original(start=False)
        admission=await self.plans.admit_start(case['raw'],task_inspection=self.inspection(),native_evidence=case['evidence'])
        await asyncio.sleep(max(0,(case['expiry']-datetime.now(timezone.utc)).total_seconds())+0.1)
        await admission.recheck(self.inspection())
        if native:
            row=copy.deepcopy(case['row']);previous=copy.deepcopy(row['ref'])
            row['ref']['revision']+=1;row['status']='revoked'
            receipt=await self.admin('identity-native-instance-set',{'authorityId':'authority-one','record':row,'previousRef':previous})
        else:
            receipt=await self.admin('identity-revoke',{'authorityId':'authority-one',
                'targetRef':strict_loads(case['raw'])['operation']['grantRef']})
        self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
        with self.assertRaisesRegex(ContractError,'execution_native_evidence_refused'):
            await admission.recheck(self.inspection())
        self.assertEqual(self.commands,[])
        self.assertEqual(self.execution_js.messages,[])
        self.assertEqual(self.credential_js.messages,[])

    async def test_current_grant_revocation_stops_admitted_completion_after_delivery_expiry(self):
        await self.completion_revocation_case(native=False)

    async def test_current_native_revocation_stops_admitted_completion_after_delivery_expiry(self):
        await self.completion_revocation_case(native=True)

    async def terminal_completion_case(self, *, expire):
        from identity.application_binding import _LocalBrowserApplicationBinding
        from identity.local_browser_session import LocalBrowserSession
        from identity.oidc_adapter import OIDCProvider
        from identity.oidc_device_authorization import OIDCDeviceAuthorizationProvider
        from identity.oidc_terminal_login import OIDCTerminalLoginOwner, OIDCTerminalSession, _SESSION
        case=await self.prepare_native_original(start=False)
        state=strict_loads((await self.service.reader.current()).record)['state']
        grant=copy.deepcopy(next(g for g in state['grants'] if g['ref']==ref('capability-process-start-grant')))
        grant.update(ref=ref('process-terminal-binding'),contractId='application-bind',resourceId='terminal-app')
        receipt=await self.admin('identity-grant-set',{'authorityId':'authority-one','record':grant,'previousRef':None})
        self.assertEqual(receipt['claims']['receipt']['decision'],'allowed')
        async def current(caller,scope):
            snapshot=await self.service.reader.current()
            return {'callerRef':caller,'scope':scope,'instanceId':'terminal-app','generation':1,'lifetimeId':'terminal-life',
                'authorityRef':{**ref('authority-one'),'revision':snapshot.sequence},'authoritySequence':snapshot.sequence,
                'validUntil':stamp(datetime.now(timezone.utc)+timedelta(seconds=5))}
        binding=_LocalBrowserApplicationBinding(SimpleNamespace(_current_local_browser_binding=current),ref('human'),self.scope)
        inner=await LocalBrowserSession.open_server_binding(binding,self.service.reader)
        # The session is real; only its fixture lifetime is shortened.
        inner._session_end=datetime.now(timezone.utc)+timedelta(seconds=12)
        provider=OIDCProvider('https://identity.example/realms/team','agentmux','key-one',
            base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='))
        config=OIDCDeviceAuthorizationProvider(provider,provider.issuer+'/device',provider.issuer+'/token')
        owner=OIDCTerminalLoginOwner(config,self.service)
        self.service.configure_oidc_terminal(owner)
        self.addAsyncCleanup(owner.close)
        session=OIDCTerminalSession(owner,inner,_SESSION);owner._sessions.add(session)
        session_id='oidc_session_'+'f'*32
        self.service._oidc_terminal_sessions[session_id]={'session':session,'caller':ref('human'),
            'scope':self.scope,'expiresAt':inner.expires_at}
        source=strict_loads(case['source']);source['operation']['terminalSessionId']=session_id
        claims=source['ingressAttestation']['claims'];claims['operation']=copy.deepcopy(source['operation'])
        source['ingressAttestation']['signature']=sign_claims(claims,SEED)
        raw,wrapper=await self.delivery(canonical_bytes(source),case['row'],case['authority_ref'],case['request_id'])
        evidence=NativeExecutionEvidence(wrapper,self.plans._ingress,canonical_bytes(ref('plugin')),'plugin-one','test-plugin',self.service)
        admission=await self.plans.admit_start(raw,task_inspection=self.inspection(),native_evidence=evidence)
        self.assertLessEqual(admission.valid_until,inner.expires_at)
        expiry=datetime.fromisoformat(strict_loads(raw)['ingressAttestation']['claims']['expiresAt'])
        await asyncio.sleep(max(0,(expiry-datetime.now(timezone.utc)).total_seconds())+0.1)
        await admission.recheck(self.inspection())
        if expire:
            await asyncio.sleep(max(0,(inner.expires_at-datetime.now(timezone.utc)).total_seconds())+0.1)
        else:session.close()
        with self.assertRaises(ContractError):await admission.recheck(self.inspection())
        with self.assertRaises(ContractError):await self.service.execution_terminal_deadline(strict_loads(raw)['operation'])
        self.assertEqual(self.commands,[])
        self.assertEqual(self.execution_js.messages,[])

    async def test_actual_terminal_session_logout_stops_admitted_completion(self):
        await self.terminal_completion_case(expire=False)

    async def test_actual_terminal_session_expiry_caps_admitted_completion(self):
        await self.terminal_completion_case(expire=True)


for _name in dir(RetainedExecutionTests):
    if _name.startswith('test_') and _name not in vars(ProcessNativeDeliveryTests):setattr(ProcessNativeDeliveryTests,_name,None)


class NativeExecutionExpiryTests(ProcessNativeDeliveryTests):
    """Each fixture makes one original finite bound the first execution ceiling."""
    def setUp(self):
        super().setUp()
        self._finite_kind=self._testMethodName.removeprefix('test_original_').removesuffix('_expiry_stops_completion')
        self._finite_end=datetime.now(timezone.utc)+timedelta(seconds=18)
        if self._finite_kind=='offline':
            self.profile['limits']['offlineSeconds']=18
            self.plans=self.make_owner()
            self.addAsyncCleanup(self.plans.close)

    def possession(self,**changes):
        raw=super().possession(**changes)
        if self._finite_kind=='task':
            value=strict_loads(raw);value['claims']['expiresAt']=stamp(self._finite_end)
            value['signature']=sign_claims(value['claims'],bytes(reversed(SEED)))
            raw=canonical_bytes(value)
        if self._finite_kind=='grant':
            grant=next(g for g in self.record['state']['grants'] if g['ref']==ref('capability-process-start-grant'))
            grant['expiresAt']=stamp(self._finite_end)
            self.sync()
        return raw

    async def enroll(self):
        if self._finite_kind=='plan':self.plan['expiresAt']=stamp(self._finite_end)
        return await super().enroll()

    def start(self,**changes):
        raw=super().start(**changes)
        if self._finite_kind!='business':return raw
        value=strict_loads(raw);value['operation']['deadline']=stamp(self._finite_end)
        claims=value['ingressAttestation']['claims']
        claims['operation']=copy.deepcopy(value['operation']);claims['expiresAt']=stamp(self._finite_end)
        value['ingressAttestation']['signature']=sign_claims(claims,SEED)
        return canonical_bytes(value)

    def install_native_policy(self,run_id):
        row=super().install_native_policy(run_id)
        if self._finite_kind=='native':
            row['facts']['grant']['expiresAt']=stamp(self._finite_end)
            row['facts']['policy']['expiresAt']=stamp(self._finite_end)
        return row

    async def finite_expiry_case(self):
        case=await self.prepare_native_original()
        first=strict_loads(case['first'])['state']
        expected=self._finite_end
        if self._finite_kind=='offline':
            task=strict_loads((await self.owner._ledger.current()).latest.record)
            expected=datetime.fromisoformat(task['state']['executionGrant']['issuedAt'])+timedelta(seconds=18)
        self.assertEqual(datetime.fromisoformat(first['admissionEnd']),expected)
        self.assertEqual(datetime.fromisoformat(first['executionBinding']['executionValidUntil']),expected)
        self.assertEqual(datetime.fromisoformat(first['nativeBinding']['businessEnd']),expected)
        self.assertLessEqual(case['public']['record']['expiresUnix'],expected.timestamp())
        admission=await self.plans.admit_start(case['raw'],task_inspection=self.inspection(),
            retained_binding=canonical_bytes(first['executionBinding']),native_evidence=case['evidence'],
            retained_native_binding=canonical_bytes(first['nativeBinding']))
        history=(tuple(m.data for m in self.execution_js.messages),tuple(m.data for m in self.credential_js.messages))
        await asyncio.sleep(max(0,(case['expiry']-datetime.now(timezone.utc)).total_seconds())+0.1)
        self.assertLess(datetime.now(timezone.utc),expected)
        current=await admission.recheck(self.inspection())
        self.assertEqual(current.valid_until,expected)
        await asyncio.sleep(max(0,(expected-datetime.now(timezone.utc)).total_seconds())+0.1)
        with self.assertRaisesRegex(ContractError,'^execution_admission_expired$'):
            await current.recheck(self.inspection())
        self.assertEqual((tuple(m.data for m in self.execution_js.messages),tuple(m.data for m in self.credential_js.messages)),history)
        self.assertEqual(self.commands,[])
        self.assertEqual(self.engine.exec_fixed.await_count,0)
        await case['execution'].cancel(self.cancel_command())
        await case['execution'].retire(await self.observe_command())
        self.assertEqual(self.execution_js.messages[0].data,case['first'])
        self.assertEqual(self.credentials._history(await self.credential_ledger.current())['record'],case['public']['record'])

    async def test_original_business_expiry_stops_completion(self):await self.finite_expiry_case()
    async def test_original_task_expiry_stops_completion(self):await self.finite_expiry_case()
    async def test_original_plan_expiry_stops_completion(self):await self.finite_expiry_case()
    async def test_original_offline_expiry_stops_completion(self):await self.finite_expiry_case()
    async def test_original_native_expiry_stops_completion(self):await self.finite_expiry_case()
    async def test_original_grant_expiry_stops_completion(self):await self.finite_expiry_case()


for _name in dir(ProcessNativeDeliveryTests):
    if _name.startswith('test_') and _name not in vars(NativeExecutionExpiryTests):setattr(NativeExecutionExpiryTests,_name,None)
